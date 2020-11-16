# Google Cloud commands

## Environment variables to create a new projecte in GCP
export ACCOUNT_NAME=<username>
export PROJECT_NAME=<name>
export PROJECT_ID=<id>
export STATE_BUCKET=<name>
export IAM_ACCOUNT=$PROJECT_NAME@$PROJECT_ID.iam.gserviceaccount.com
export TF_VAR_project_id=$PROJECT_ID
export TF_VAR_state_bucket=$STATE_BUCKET
export TF_VAR_email_address=<email>
export TF_VAR_slack_auth_token=<hash>

## Better add environment variables in an .env file and source it
source .env

## Project ID Hash
export TF_VAR_project_id=$PROJECT_NAME-$(date +%Y%m%d%H%M%S)
echo $TF_VAR_project_id

## State bucket terraform variable
export TF_VAR_state_bucket=$PROJECT_NAME-tfstate-$(date +%Y%m%d%H%M%S)
echo $TF_VAR_state_bucket


## Login to GCP
gcloud auth application-default login

## Create new project
gcloud projects create $PROJECT_ID

## Check new project once created
gcloud projects list

## Create new service account
gcloud iam service-accounts \
    create $PROJECT_NAME \
    --project $PROJECT_ID \
    --display-name $PROJECT_NAME

## Check newly created service account
gcloud iam service-accounts list \
    --project $PROJECT_ID

## Create a credentias JSON file
gcloud iam service-accounts \
    keys create account.json \
    --iam-account $IAM_ACCOUNT \
    --project $PROJECT_ID

## Grant permissions to new service account
gcloud projects \
    add-iam-policy-binding $PROJECT_ID \
    --member serviceAccount:$IAM_ACCOUNT \
    --role roles/editor
    
## Enable GCP Compute Engine API
open https://console.developers.google.com/apis/library/compute.googleapis.com?project=$PROJECT_ID

## Create a GCP monitoring workspace
open https://console.cloud.google.com/monitoring

## Terraform commands
terraform validate
terraform fmt
terraform plan
terraform apply
terraform ouput

## Generate SSH key pair certs for ansible operator user
ssh-keygen -b 2048 -t rsa -f creds/id_rsa -q -N ""

## Check ansible connectivity to remote instance
ansible prod -i <host> -u ansible -m setup -a 'filter=ansible_hostname'
ansible prod -i <host> -u ansible -m setup -a 'filter=ansible_distribution_release'

## Ansible manual playbook execution
ansible-playbook -i <host> playbook.yml
ansible-playbook -i <host> --private-key <private_key>  -e 'ansible_python_interpreter=/usr/bin/python3' ../ansible/playbook.yml"

## Ansible manual playbook execution with vault decryption
ansible-playbook -i <host> --vault-password-file=vault_pass --private-key <private_key>  -e 'ansible_python_interpreter=/usr/bin/python3' ../ansible/playbook.yml"

## Encrypt/decrypt ansible secret variables
cp ansible/vars/secret.yml.dist ansible/vars/secret.yml
ansible-vault encrypt ansible/vars/secret.yml
ansible-vault decrypt ansible/vars/secret.yml

## Enable HTTPS on WordPress by adding this line to wp-config.php file
```if ($_SERVER['HTTP_X_FORWARDED_PROTO'] == 'https') $_SERVER['HTTPS']='on';```

Proceed wordpress installation the first time
