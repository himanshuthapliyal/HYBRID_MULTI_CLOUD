provider "aws"{
	region ="ap-south-1"
	profile="goel"
}


resource "tls_private_key" "myweb_key" {
  algorithm   = "RSA"
  rsa_bits = 4096
}

resource "local_file" "rocks" {
    filename = "fsociety.pem"
}

resource "aws_key_pair" "myweb_key" {
  key_name   = "fsociety"
  public_key = tls_private_key.myweb_key.public_key_openssh  
}





resource "aws_instance"  "myweb" {
  ami           = "ami-0447a12f28fddb066"
  instance_type = "t2.micro"
  key_name	=  aws_key_pair.myweb_key.key_name
  security_groups =  [ "security_keyname" ] 
  
connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key =  tls_private_key.myweb_key.private_key_pem
    host     = aws_instance.myweb.public_ip
  }

  provisioner "remote-exec" {
    inline = [
      "sudo yum install httpd  php git -y",
      "sudo systemctl restart httpd",
      "sudo systemctl enable httpd",
    ]
  }

tags = {
    Name = "kotdwara"
  }
}



resource "aws_security_group" "hg_goel" {
  name        = "security_keyname"
  description = "Allow TCP inbound traffic"
  vpc_id      = "vpc-2feaf747"


  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [ "0.0.0.0/0" ]
  }

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [ "0.0.0.0/0" ]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "goel_rocks"
  }
}



resource "aws_ebs_volume" "my_ebs" {
	availability_zone = aws_instance.myweb.availability_zone
	size              = 1

  tags = {
    Name = "ebs"
  }
}


resource "aws_volume_attachment" "ebs_att" {
	device_name = "/dev/sdh"
  	volume_id   = aws_ebs_volume.my_ebs.id
	instance_id = aws_instance.myweb.id
  	
}



resource "null_resource" "nullremote3"  {

depends_on = [
    aws_volume_attachment.ebs_att,
  ]


  connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key =  tls_private_key.myweb_key.private_key_pem
    host     = aws_instance.myweb.public_ip
  }

provisioner "remote-exec" {
    inline = [
      "sudo mkfs.ext4  /dev/xvdh",
      "sudo mount  /dev/xvdh  /var/www/html",
      "sudo rm -rf /var/www/html/*",
      "sudo git clone https://github.com/himanshuthapliyal/RIGHT_EDU.git  /var/www/html/"
    ]
  }
}






//----------------------------------------------------------------------------------------------------------------------------------------------






resource "aws_s3_bucket" "my-terra-bucket-88448844" {
	bucket = "my-terra-bucket-88448844"
        acl = "public-read"


 provisioner "local-exec" {
        command     = "git clone https://github.com/himanshuthapliyal/RIGHT_EDU  GIT_PULLL"
    }

 provisioner "local-exec" {
        when        =   destroy
        command     =   "echo Y | rmdir /s GIT_PULLL"
    }

}


resource "aws_s3_bucket_object" "image-pull" {

    bucket  = aws_s3_bucket.my-terra-bucket-88448844.bucket
    key     = "hello.jpg"
    source  = "GIT_PULLL/NmDIPyO_.jpg"
    acl     = "public-read"
}




//------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

//cloud front 




locals {
  s3_origin_id = aws_s3_bucket.my-terra-bucket-88448844.bucket
  image_url = "${aws_cloudfront_distribution.my_s3_distribution.domain_name}/${aws_s3_bucket_object.image-pull.key}"
}



resource "aws_cloudfront_distribution" "my_s3_distribution" {
  origin {
    domain_name = aws_s3_bucket.my-terra-bucket-88448844.bucket_regional_domain_name
    origin_id   = local.s3_origin_id

    s3_origin_config {
      origin_access_identity = "origin-access-identity/cloudfront/E1MXIMYYQQ67SI"
    }
  }

  enabled             = true
  is_ipv6_enabled     = true
  default_root_object = "hybrid_multi_cloud.html"


default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = local.s3_origin_id

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }


viewer_protocol_policy = "allow-all"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
  }

restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

viewer_certificate {
    cloudfront_default_certificate = true
  }



connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key =  tls_private_key.myweb_key.private_key_pem
    host     = aws_instance.myweb.public_ip
  }

provisioner "remote-exec" {
        inline  = [
            "sudo su << EOF",
            "echo \"<img src='http://${self.domain_name}/${aws_s3_bucket_object.image-pull.key}'>\" >> /var/www/html/index.php",
            "EOF"
        ]
    }

}





resource "null_resource" "lcal_local"  {


depends_on = [
    aws_cloudfront_distribution.my_s3_distribution,
  ]

	provisioner "local-exec" {
	    command = "start chrome  ${aws_instance.myweb.public_ip}"
  	}
}









