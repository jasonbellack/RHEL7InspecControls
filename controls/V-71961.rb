control "xccdf_mil.disa.stig_rule_SV-86585r5_rule" do
  title "Red Hat Enterprise Linux operating systems prior to version 7.2 with a Basic Input/Output System (BIOS) must require authentication upon booting into single-user and maintenance modes."
  desc  "
    Vulnerability Discussion: If the system does not require valid root authentication before it boots into single-user or maintenance mode, anyone who invokes single-user or maintenance mode is granted privileged access to all files on the system. GRUB 2 is the default boot loader for RHEL 7 and is designed to require a password to boot into single-user mode or make modifications to the boot menu.
    
    Documentable: false
    
  "
  impact 1.0
  describe.one do
    describe file("/etc/redhat-release") do
      its("content") { should_not match(/^Red Hat Enterprise Linux.*release\s+(\S+)\s+/) }
    end
    file("/etc/redhat-release").content.to_s.scan(/^Red Hat Enterprise Linux.*release\s+(\S+)\s+/).flatten.each do |entry|
      describe entry do
        it { should_not eq "7.0" }
      end
    end
    file("/etc/redhat-release").content.to_s.scan(/^Red Hat Enterprise Linux.*release\s+(\S+)\s+/).flatten.each do |entry|
      describe entry do
        it { should_not eq "7.1" }
      end
    end
    describe file("/boot/grub2/grub.cfg") do
      it { should_not exist }
    end
    describe file("/boot/grub2/grub.cfg") do
      its("content") { should match(/^[\s]*password_pbkdf2[\s]+.*[\s]+grub\.pbkdf2\.sha512.*$/) }
      its("content") { should match(/^[\s]*set[\s]+superusers=\"[^"]*\"$/) }
    end
  end
end
