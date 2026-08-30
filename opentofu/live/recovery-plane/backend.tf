terraform {
  # root-trust creates this bucket; CI injects its reviewed bucket and prefix.
  backend "gcs" {}
}
