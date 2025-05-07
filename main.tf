# Upload files to existing GCS bucket.
locals {
  files_to_upload = [
    {
      gcs_name   = "test.txt"
      local_path = "test.txt"
    },
    
    {
      gcs_name   = "kube.jpg"
      local_path = "kube.jpg"
    }, 

    {
      gcs_name = "eeee.txt"
      local_path = "../Upload-Files/eeee.txt"
    }
  ]
}

# Upload multiple files to an existing GCS bucket using a for_each loop 
resource "google_storage_bucket_object" "upload_multiple" {
  for_each = { for item in local.files_to_upload : item.gcs_name => item }

  name   = each.key
  bucket = "${google_storage_bucket.name.name}"
  source = each.value.local_path
}

resource "google_storage_bucket" "name" {
  name     = "test-1-jagan_kuram_sa" # Replace with your desired bucket name (must be globally unique)
  location = "US-CENTRAL1"             # Replace with your desired bucket location
  # Add other bucket configurations as needed
}
