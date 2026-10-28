import json
from unittest import mock

from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.test import APIClient, APITestCase

from apps.audit.admin_events import record_admin_event
from apps.audit.models import AuditEvent
from apps.audit.redaction import REDACTED
from apps.issues.models import IssueReport
from apps.rbac.models import Role

User = get_user_model()


def fake_gh_token() -> str:
    """A GitHub-token-shaped string built at runtime, not a real token."""
    return "ghp_" + "Ab1Cd2Ef3G" * 4


class RecordAdminEventTests(APITestCase):
    def setUp(self):
        self.admin = User.objects.create_superuser(
            username="boss", email="boss@example.com", password="pw-for-tests-1"
        )

    def _request(self, user=None, request_id="req-123"):
        request = mock.Mock()
        request.user = user
        request.request_id = request_id
        return request

    def test_event_shape(self):
        event = record_admin_event(
            operation="issue.updated",
            action="updated",
            target_type="issues.issuereport",
            target_id=7,
            request=self._request(self.admin),
            payload={"changes": {"status": {"from": "Open", "to": "Closed"}}},
            summary="Updated issue report #7",
        )
        event.refresh_from_db()
        self.assertEqual(event.actor, self.admin)
        self.assertEqual(event.action, "updated")
        self.assertEqual(event.resource_type, "issues.issuereport")
        self.assertEqual(event.resource_id, "7")
        self.assertEqual(event.correlation_id, "req-123")
        self.assertIsNotNone(event.created_at)
        self.assertEqual(event.extra["operation"], "issue.updated")
        self.assertEqual(event.extra["source"], "admin_action")
        self.assertEqual(event.extra["summary"], "Updated issue report #7")
        self.assertEqual(
            event.extra["payload"],
            {"changes": {"status": {"from": "Open", "to": "Closed"}}},
        )
        # client details are deliberately not stored
        self.assertIsNone(event.ip_address)
        self.assertEqual(event.user_agent, "")
        self.assertIsNone(event.before)
        self.assertIsNone(event.after)

    def test_payload_is_redacted_before_it_is_stored(self):
        token = fake_gh_token()
        event = record_admin_event(
            operation="issue.updated",
            action="updated",
            target_type="issues.issuereport",
            target_id=1,
            actor=self.admin,
            payload={"password": "hunter2", "title": f"oops {token}"},
        )
        stored = json.dumps(AuditEvent.objects.get(pk=event.pk).extra)
        self.assertNotIn("hunter2", stored)
        self.assertNotIn(token, stored)
        self.assertIn(REDACTED, stored)

    def test_anonymous_or_missing_actor_is_stored_as_null(self):
        from django.contrib.auth.models import AnonymousUser

        event = record_admin_event(
            operation="x.y",
            action="created",
            target_type="a.b",
            target_id=1,
            request=self._request(AnonymousUser()),
        )
        self.assertIsNone(event.actor)

    def test_unknown_action_does_not_raise(self):
        before = AuditEvent.objects.count()
        result = record_admin_event(
            operation="x.y", action="exploded", target_type="a.b", target_id=1
        )
        self.assertIsNone(result)
        self.assertEqual(AuditEvent.objects.count(), before)

    def test_database_failure_does_not_raise(self):
        with mock.patch(
            "apps.audit.admin_events.AuditEvent.objects.create",
            side_effect=RuntimeError("db is down"),
        ):
            with self.assertLogs("apps.audit.admin_events", level="ERROR"):
                result = record_admin_event(
                    operation="x.y", action="created", target_type="a.b", target_id=1
                )
        self.assertIsNone(result)

    def test_unserialisable_payload_does_not_raise(self):
        class Boom:
            def __str__(self):
                raise RuntimeError("no string for you")

        result = record_admin_event(
            operation="x.y",
            action="created",
            target_type="a.b",
            target_id=1,
            payload={"x": Boom()},
        )
        self.assertIsNone(result)


class AdminActionEmissionTests(APITestCase):
    def setUp(self):
        self.admin = User.objects.create_superuser(
            username="boss", email="boss@example.com", password="pw-for-tests-1"
        )
        self.member = User.objects.create_user(
            username="member", email="member@example.com", password="pw-for-tests-2"
        )
        self.client.force_authenticate(user=self.admin)
        self.issue = IssueReport.objects.create(
            title="Broken link",
            description="Clicking the link gives a 404 page and nothing else.",
            issue_type="Bug",
        )

    def _events(self, operation):
        return AuditEvent.objects.filter(extra__operation=operation)

    # issue management

    def test_issue_update_emits_event_with_request_id(self):
        response = self.client.patch(
            f"/api/issues/{self.issue.pk}/",
            {"status": "Resolved"},
            format="json",
            HTTP_X_REQUEST_ID="req-abc-1",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        event = self._events("issue.updated").get()
        self.assertEqual(event.actor, self.admin)
        self.assertEqual(event.action, "updated")
        self.assertEqual(event.resource_type, "issues.issuereport")
        self.assertEqual(event.resource_id, str(self.issue.pk))
        self.assertEqual(event.correlation_id, "req-abc-1")
        self.assertEqual(
            event.extra["payload"],
            {"changes": {"status": {"from": "Open", "to": "Resolved"}}},
        )

    def test_issue_update_does_not_store_free_text(self):
        new_text = "A completely different description with private details."
        self.client.patch(
            f"/api/issues/{self.issue.pk}/", {"description": new_text}, format="json"
        )
        event = self._events("issue.updated").get()
        self.assertEqual(
            event.extra["payload"], {"changes": {"description": {"changed": True}}}
        )
        stored = json.dumps(event.extra)
        self.assertNotIn(new_text, stored)
        self.assertNotIn(self.issue.description, stored)

    def test_issue_update_redacts_a_token_pasted_into_the_title(self):
        token = fake_gh_token()
        self.client.patch(
            f"/api/issues/{self.issue.pk}/",
            {"title": f"login broken, token {token}"},
            format="json",
        )
        event = self._events("issue.updated").get()
        self.assertNotIn(token, json.dumps(event.extra))

    def test_issue_delete_emits_event(self):
        pk = self.issue.pk
        response = self.client.delete(f"/api/issues/{pk}/")
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        event = self._events("issue.deleted").get()
        self.assertEqual(event.action, "deleted")
        self.assertEqual(event.resource_id, str(pk))
        self.assertEqual(event.actor, self.admin)
        self.assertEqual(event.extra["payload"]["title"], "Broken link")

    def test_rejected_issue_update_emits_nothing(self):
        self.client.force_authenticate(user=self.member)
        response = self.client.patch(
            f"/api/issues/{self.issue.pk}/", {"status": "Closed"}, format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertFalse(
            AuditEvent.objects.filter(extra__source="admin_action").exists()
        )

    def test_issue_update_still_works_when_the_audit_write_fails(self):
        with mock.patch(
            "apps.audit.admin_events.AuditEvent.objects.create",
            side_effect=RuntimeError("audit table is down"),
        ):
            with self.assertLogs("apps.audit.admin_events", level="ERROR"):
                response = self.client.patch(
                    f"/api/issues/{self.issue.pk}/",
                    {"status": "Closed"},
                    format="json",
                )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.issue.refresh_from_db()
        self.assertEqual(self.issue.status, "Closed")

    # user / role management

    def test_role_assign_and_revoke_emit_events(self):
        role = Role.objects.create(name="Reviewer")
        body = {"user_id": self.member.pk, "role_id": role.pk}

        response = self.client.post("/api/rbac/assign/", body, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        assigned = self._events("user.role_assigned").get()
        self.assertEqual(assigned.actor, self.admin)
        self.assertEqual(assigned.action, "created")
        self.assertEqual(assigned.resource_type, "auth.user")
        self.assertEqual(assigned.resource_id, str(self.member.pk))
        self.assertEqual(assigned.extra["payload"]["role_name"], "Reviewer")
        self.assertTrue(assigned.correlation_id)

        # assigning twice changes nothing, so no second event
        self.client.post("/api/rbac/assign/", body, format="json")
        self.assertEqual(self._events("user.role_assigned").count(), 1)

        response = self.client.post("/api/rbac/revoke/", body, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        revoked = self._events("user.role_revoked").get()
        self.assertEqual(revoked.action, "deleted")
        self.assertEqual(revoked.resource_id, str(self.member.pk))

    def test_role_assign_still_works_when_the_audit_write_fails(self):
        role = Role.objects.create(name="Reviewer")
        with mock.patch(
            "apps.audit.admin_events.AuditEvent.objects.create",
            side_effect=RuntimeError("audit table is down"),
        ):
            with self.assertLogs("apps.audit.admin_events", level="ERROR"):
                response = self.client.post(
                    "/api/rbac/assign/",
                    {"user_id": self.member.pk, "role_id": role.pk},
                    format="json",
                )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(self.member.user_roles.filter(role=role).exists())


class AdminEventReadAccessTests(APITestCase):
    def setUp(self):
        self.admin = User.objects.create_user(
            username="staff", email="staff@example.com", password="pw-1", is_staff=True
        )
        self.member = User.objects.create_user(
            username="plain", email="plain@example.com", password="pw-2"
        )
        self.event = record_admin_event(
            operation="issue.updated",
            action="updated",
            target_type="issues.issuereport",
            target_id=1,
            actor=self.admin,
            payload={"changes": {"status": {"from": "Open", "to": "Closed"}}},
        )
        record_admin_event(
            operation="user.role_assigned",
            action="created",
            target_type="auth.user",
            target_id=2,
            actor=self.admin,
        )

    def test_staff_can_read_list_and_detail(self):
        self.client.force_authenticate(user=self.admin)
        listing = self.client.get("/api/admin/audit/")
        self.assertEqual(listing.status_code, status.HTTP_200_OK)
        detail = self.client.get(f"/api/admin/audit/{self.event.pk}/")
        self.assertEqual(detail.status_code, status.HTTP_200_OK)
        self.assertEqual(detail.data["extra"]["operation"], "issue.updated")
        self.assertEqual(detail.data["summary"], "Updated Issuereport #1")

    def test_regular_user_cannot_read_list_or_detail(self):
        self.client.force_authenticate(user=self.member)
        self.assertEqual(
            self.client.get("/api/admin/audit/").status_code,
            status.HTTP_403_FORBIDDEN,
        )
        self.assertEqual(
            self.client.get(f"/api/admin/audit/{self.event.pk}/").status_code,
            status.HTTP_403_FORBIDDEN,
        )

    def test_anonymous_cannot_read_list_or_detail(self):
        anon = APIClient()
        self.assertEqual(
            anon.get("/api/admin/audit/").status_code, status.HTTP_401_UNAUTHORIZED
        )
        self.assertEqual(
            anon.get(f"/api/admin/audit/{self.event.pk}/").status_code,
            status.HTTP_401_UNAUTHORIZED,
        )

    def test_filter_by_operation(self):
        self.client.force_authenticate(user=self.admin)
        response = self.client.get("/api/admin/audit/?operation=user.role_assigned")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 1)
        self.assertEqual(
            response.data["results"][0]["extra"]["operation"], "user.role_assigned"
        )
