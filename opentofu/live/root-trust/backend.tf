terraform {
  # The bucket and prefix are injected with -backend-config after the one-time,
  # reviewed local-state bootstrap creates both protected backend buckets.
  backend "gcs" {}
}
