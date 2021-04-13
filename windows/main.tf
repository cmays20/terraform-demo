terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
      version = "~> 2.70"
    }
  }
}

provider "aws" {
  profile = "default"
  region = "us-east-2"
}

# Default security group to access the instances via WinRM over HTTP and HTTPS
resource "aws_security_group" "default" {
  name        = "windows_ad"
  description = "Used in the terraform"

  # WinRM access from anywhere
  ingress {
    from_port   = 5985
    to_port     = 5986
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # outbound internet access
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "windows_ad" {
  ami = "ami-00d1b5cc1e5341681"
  instance_type = "t2.micro"
  tags = {
    Name = "Windows-AD"
    owner = "cmays"
    AOC_DEMO_ROLE = "ad"
    DemoID = "cmays"
  }
  key_name = "deployer-key"

  # Our Security group to allow WinRM access
  vpc_security_group_ids = [aws_security_group.default.id]

  user_data = <<EOF
<powershell>
  Set-Item -Path WSMan:\localhost\Service\Auth\Certificate -Value $true
  Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value $true
  Set-Item -Path WSMan:\localhost\Service\AllowUnencrypted -Value $true
  netsh advfirewall firewall add rule name="WinRM in" protocol=TCP dir=in profile=any localport=5985 remoteip=any localip=any action=allow
  $testUserAccountName = '${var.win_username}'
  $testUserAccountPassword = (ConvertTo-SecureString -String '${var.win_password}' -AsPlainText -Force)
  if (-not (Get-LocalUser -Name $testUserAccountName -ErrorAction Ignore)) {
    $newUserParams = @{
        Name                 = $testUserAccountName
        AccountNeverExpires  = $true
        PasswordNeverExpires = $true
        Password             = $testUserAccountPassword
    }
    $null = New-LocalUser @newUserParams
  }

  $newItemParams = @{
      Path         = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
      Name         = 'LocalAccountTokenFilterPolicy'
      Value        = 1
      PropertyType = 'DWORD'
      Force        = $true
  }
  $null = New-ItemProperty @newItemParams

  Get-LocalUser -Name $testUserAccountName | Add-LocalGroupMember -Group 'Administrators'
</powershell>
EOF
}

# Default security group to access the instances via WinRM over HTTP and HTTPS
resource "aws_security_group" "windows_iis_sg" {
  name        = "windows_iis"
  description = "Used in the terraform"

  # WinRM access from anywhere
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # outbound internet access
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "windows_iis" {
  ami = "ami-00d1b5cc1e5341681"
  instance_type = "t2.micro"
  tags = {
    Name = "Windows-IIS"
    owner = "cmays"
    AOC_DEMO_ROLE = "iis"
    DemoID = "cmays"
  }
  key_name = "deployer-key"

  # Our Security group to allow WinRM access
  vpc_security_group_ids = [aws_security_group.windows_iis_sg.id]

  user_data = <<EOF
<powershell>
  Set-Item -Path WSMan:\localhost\Service\Auth\Certificate -Value $true
  Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value $true
  Set-Item -Path WSMan:\localhost\Service\AllowUnencrypted -Value $true
  netsh advfirewall firewall add rule name="WinRM in" protocol=TCP dir=in profile=any localport=5985 remoteip=any localip=any action=allow
  $testUserAccountName = '${var.win_username}'
  $testUserAccountPassword = (ConvertTo-SecureString -String '${var.win_password}' -AsPlainText -Force)
  if (-not (Get-LocalUser -Name $testUserAccountName -ErrorAction Ignore)) {
    $newUserParams = @{
        Name                 = $testUserAccountName
        AccountNeverExpires  = $true
        PasswordNeverExpires = $true
        Password             = $testUserAccountPassword
    }
    $null = New-LocalUser @newUserParams
  }

  $newItemParams = @{
      Path         = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
      Name         = 'LocalAccountTokenFilterPolicy'
      Value        = 1
      PropertyType = 'DWORD'
      Force        = $true
  }
  $null = New-ItemProperty @newItemParams

  Get-LocalUser -Name $testUserAccountName | Add-LocalGroupMember -Group 'Administrators'
</powershell>
EOF
}

resource "aws_key_pair" "deployer" {
  key_name = "deployer-key"
  public_key = var.public_key
}
