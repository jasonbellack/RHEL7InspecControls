control "xccdf_mil.disa.stig_rule_SV-86587r4_rule" do
  title "Red Hat Enterprise Linux operating systems prior to version 7.2 using Unified Extensible Firmware Interface (UEFI) must require authentication upon booting into single-user and maintenance modes."
  desc  "
    Vulnerability Discussion: If the system does not require valid root authentication before it boots into single-user or maintenance mode, anyone who invokes single-user or maintenance mode is granted privileged access to all files on the system. GRUB 2 is the default boot loader for RHEL 7 and is designed to require a password to boot into single-user mode or make modifications to the boot menu.
    
    Documentable: false
    
  "
  impact 1.0
  describe.one do
    describe file("/boot/efi/EFI/redhat/grub.cfg") do
        it { should exist }
    end
    describe file("/etc/grub.d/40_custom") do
        its("content") { should match('set superusers="root"') }
        its("content") { should match("password_pbkdf2 root {hash from grub2-mkpasswd-pbkdf2 command}") }
    end
  end
end
