terraform {
  required_version = ">= 1.5, < 2"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "6.50.0"
    }
  }
}
# The GCP project ID stays out of tracked files; supply it from an ignored tfvars file.
variable "project" {
  type        = string
  description = "GCP project ID"
}
provider "google" {
  project = var.project
  region  = "asia-southeast1"
}
resource "google_service_account" "runtime" {
  account_id   = "gate-runtime"
  display_name = "Gate runtime"
}
resource "google_firestore_database" "gate" {
  project                 = var.project
  name                    = "gate"
  location_id             = "asia-southeast1"
  type                    = "FIRESTORE_NATIVE"
  concurrency_mode        = "PESSIMISTIC"
  delete_protection_state = "DELETE_PROTECTION_ENABLED"
  deletion_policy         = "ABANDON"
  lifecycle { prevent_destroy = true }
}
resource "google_project_iam_member" "database" {
  project = var.project
  role    = "roles/datastore.user"
  member  = "serviceAccount:${google_service_account.runtime.email}"
  condition {
    title       = "gate-database-only"
    description = "Gate database access only"
    expression  = "resource.name==\"projects/${var.project}/databases/gate\""
  }
}
resource "google_firestore_field" "artifact_ttl" {
  project    = var.project
  database   = google_firestore_database.gate.name
  collection = "entries"
  field      = "expiresAt"
  ttl_config {}
}
# TTL deletion is asynchronous; application reads continue to enforce expiresAt.
resource "google_firestore_field" "browser_login_attempt_ttl" {
  project    = var.project
  database   = google_firestore_database.gate.name
  collection = "gate_browser_login_attempts"
  field      = "expiresAt"
  ttl_config {}
}
resource "google_firestore_field" "browser_approval_ttl" {
  project    = var.project
  database   = google_firestore_database.gate.name
  collection = "gate_browser_approvals"
  field      = "expiresAt"
  ttl_config {}
}
resource "google_firestore_field" "browser_session_ttl" {
  project    = var.project
  database   = google_firestore_database.gate.name
  collection = "gate_browser_sessions"
  field      = "expiresAt"
  ttl_config {}
}
resource "google_firestore_field" "identity_session_ttl" {
  project    = var.project
  database   = google_firestore_database.gate.name
  collection = "gate_identity_sessions"
  field      = "expiresAt"
  ttl_config {}
}
resource "google_firestore_field" "confirmation_ttl" {
  project    = var.project
  database   = google_firestore_database.gate.name
  collection = "gate_confirmations"
  field      = "expiresAt"
  ttl_config {}
}
resource "google_firestore_field" "confirmation_reference_ttl" {
  project    = var.project
  database   = google_firestore_database.gate.name
  collection = "gate_confirmation_references"
  field      = "expiresAt"
  ttl_config {}
}
resource "google_artifact_registry_repository" "gate" {
  project       = var.project
  location      = "asia-southeast1"
  repository_id = "gate"
  format        = "DOCKER"
}
locals {
  secret_names = toset(["gate-github-client-id", "gate-github-client-secret", "gate-cookie-keys", "gate-jwks", "gate-resources"])
}
resource "google_secret_manager_secret" "runtime" {
  for_each  = local.secret_names
  project   = var.project
  secret_id = each.key
  replication {
    auto {}
  }
  lifecycle { prevent_destroy = true }
}
resource "google_secret_manager_secret_iam_member" "runtime" {
  for_each  = google_secret_manager_secret.runtime
  project   = var.project
  secret_id = each.value.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.runtime.email}"
}
