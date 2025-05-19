# AWS Resource Discovery and Terraform Import Script

This script automates the discovery of AWS resources in your account, generates Terraform configuration files, and prepares import commands to bring existing AWS resources under Terraform management. Default AWS resources (such as default VPCs, subnets, and security groups) are excluded.

## Prerequisites
- **AWS CLI** installed and configured (`aws configure`)
- **Terraform** installed (v1.0+ recommended)
- **jq** installed
- Sufficient AWS permissions to list and describe resources

## Usage

1. **Make the script executable:**
   ```bash
   chmod +x modified-aws-terraform-script.sh
   ```

2. **Run the script:**
   ```bash
   ./modified-aws-terraform-script.sh
   ```
   - The script will check dependencies, verify AWS access, and prompt you to select a region.
   - It will generate a `terraform-aws-modules` directory with all Terraform configuration and an `import_commands.sh` script.

3. **Change to the generated directory:**
   ```bash
   cd terraform-aws-modules
   ```

4. **Initialize Terraform:**
   ```bash
   terraform init
   ```

5. **Import existing AWS resources into Terraform state:**
   ```bash
   ./import_commands.sh
   ```

6. **Validate the configuration:**
   ```bash
   terraform validate
   ```

7. **Review and plan changes:**
   ```bash
   terraform plan
   ```

8. **(Optional) Apply the configuration:**
   ```bash
   terraform apply
   ```

## Notes
- **Manual Review:** Some resources (e.g., IAM policies, Lambda code, RDS passwords) may require manual editing in the generated `.tf` files.
- **Default Resources:** Default AWS resources are intentionally excluded.
- **Import Order:** The import script uses module addresses for all resources.
- **State Management:** After import, Terraform will manage your resources. Review the plan before applying changes.

## Troubleshooting
- If you see errors about missing resources during import, ensure you are using the correct module-prefixed resource addresses (the script handles this automatically).
- If you encounter permission errors, check your AWS credentials and permissions.

## Copying Files to Local Machine
To copy the generated Terraform files from a remote server to your local machine, use:
```bash
scp -r ubuntu@<REMOTE_SERVER_IP>:~/terraform-aws-modules /path/to/local/destination
```

---

**Author:** Your Name
