from rest_framework import permissions, viewsets
from rest_framework.parsers import FormParser, JSONParser, MultiPartParser

from apps.audit.admin_events import (
    ISSUE_DELETED,
    ISSUE_UPDATED,
    record_admin_event,
    target_type_for,
)
from apps.issues.models import IssueReport
from apps.issues.serializers import IssueReportSerializer

# Fields whose old and new value are written to the audit event. Everything
# else (description, url_path, image) is user supplied free text or a file, so
# only the fact that it changed is recorded.
_AUDIT_VALUE_FIELDS = {"title", "status", "issue_type", "is_verified"}


def _plain(value):
    """FieldFile and friends to something comparable and JSON-safe."""
    name = getattr(value, "name", None)
    if name is not None and not isinstance(value, str):
        return name
    return value


class IssueReportViewSet(viewsets.ModelViewSet):
    queryset = IssueReport.objects.all()
    serializer_class = IssueReportSerializer
    parser_classes = (MultiPartParser, FormParser, JSONParser)

    # Allow anyone to create a report (anonymous or authenticated)
    permission_classes = [permissions.AllowAny]

    def get_permissions(self):
        # Restrict reading and updating to admins/staff
        if self.action in ["list", "retrieve", "update", "partial_update", "destroy"]:
            return [permissions.IsAdminUser()]
        return super().get_permissions()

    def perform_create(self, serializer):
        instance = serializer.save()
        self._check_and_award_bug_hunter_badge(instance)

    def perform_update(self, serializer):
        before = {
            field: _plain(getattr(serializer.instance, field, None))
            for field in serializer.validated_data
        }
        instance = serializer.save()
        self._record_update(instance, before)
        self._check_and_award_bug_hunter_badge(instance)

    def perform_destroy(self, instance):
        target_id = instance.pk
        snapshot = {
            "title": instance.title,
            "status": instance.status,
            "issue_type": instance.issue_type,
        }
        super().perform_destroy(instance)
        record_admin_event(
            operation=ISSUE_DELETED,
            action="deleted",
            target_type=target_type_for(IssueReport),
            target_id=target_id,
            request=self.request,
            payload=snapshot,
            summary=f"Deleted issue report #{target_id}",
        )

    def _record_update(self, instance, before):
        """Audit an admin edit: values for a few safe fields, names for the rest."""
        changes = {}
        for field, old in before.items():
            new = _plain(getattr(instance, field, None))
            if old == new:
                continue
            if field in _AUDIT_VALUE_FIELDS:
                changes[field] = {"from": old, "to": new}
            else:
                changes[field] = {"changed": True}
        record_admin_event(
            operation=ISSUE_UPDATED,
            action="updated",
            target_type=target_type_for(instance),
            target_id=instance.pk,
            request=self.request,
            payload={"changes": changes},
            summary=f"Updated issue report #{instance.pk}",
        )

    def _check_and_award_bug_hunter_badge(self, instance):
        if instance.user and instance.is_verified:
            verified_count = IssueReport.objects.filter(
                user=instance.user, is_verified=True
            ).count()
            if verified_count >= 3:
                from apps.gamification.services import award_badge_service

                award_badge_service(instance.user, badge_name="Bug Hunter")


from django.db import transaction
from django_q.tasks import async_task
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.response import Response

from apps.issues.models import Bounty, BountySubmission
from apps.issues.serializers import BountySerializer, BountySubmissionSerializer
from apps.progress.models import XPEvent, XPMultiplierEvent


class BountyViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Bounty.objects.select_related("badge").all()
    serializer_class = BountySerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]

    @action(
        detail=True, methods=["post"], permission_classes=[permissions.IsAuthenticated]
    )
    def claim(self, request, pk=None):
        with transaction.atomic():
            try:
                bounty = Bounty.objects.select_for_update().get(pk=pk)
            except Bounty.DoesNotExist:
                return Response(
                    {"error": "Bounty not found."},
                    status=status.HTTP_404_NOT_FOUND,
                )

            if bounty.status != Bounty.Status.OPEN:
                return Response(
                    {"error": "Bounty is not open for claiming."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            bounty.status = Bounty.Status.CLAIMED
            bounty.claimed_by = request.user
            bounty.save()

        return Response({"status": "Bounty claimed successfully!"})

    @action(
        detail=True, methods=["post"], permission_classes=[permissions.IsAuthenticated]
    )
    def submit(self, request, pk=None):
        bounty = self.get_object()

        if bounty.status != Bounty.Status.CLAIMED or bounty.claimed_by != request.user:
            return Response(
                {"error": "You must claim this bounty before submitting."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        code_patch = request.data.get("code_patch", "")
        if not code_patch:
            return Response(
                {"error": "No code submitted."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        with transaction.atomic():
            submission = BountySubmission.objects.create(
                bounty=bounty,
                user=request.user,
                code_patch=code_patch,
                status=BountySubmission.Status.PASSED,
            )

            bounty.status = Bounty.Status.COMPLETED
            bounty.save()

            # Award XP
            multiplier = XPMultiplierEvent.get_active_multiplier()
            xp_earned = int(bounty.xp_reward * multiplier)
            XPEvent.objects.create(
                user=request.user,
                source_type="bounty",
                source_id=bounty.id,
                base_points=bounty.xp_reward,
                multiplier=multiplier,
                xp_delta=xp_earned,
            )

            # Award badge asynchronously if the bounty has one configured
            if bounty.badge_id:
                async_task(
                    "apps.progress.tasks.award_specific_badge",
                    request.user.id,
                    bounty.badge_id,
                )

        return Response(
            {
                "status": "Bounty completed successfully!",
                "xp_earned": xp_earned,
            }
        )
