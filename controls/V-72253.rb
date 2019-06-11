control "xccdf_mil.disa.stig_rule_SV-86877r3_rule" do
  title "The Red Hat Enterprise Linux operating system must be configured so that the SSH daemon is configured to only use Message Authentication Codes (MACs) employing FIPS 140-2 approved cryptographic hash algorithms."
  desc  "
    Vulnerability Discussion: DoD information systems are required to use FIPS 140-2 approved cryptographic hash functions. The only SSHv2 hash algorithm meeting this requirement is SHA.
    
    Documentable: false
    
  "
  impact 0.5
  only_if { package("openssh-server").installed? }
  
  describe sshd_config("/etc/ssh/sshd_config") do
    its ("MACs") { should_not be_nil }
  end
  
  configured_macs = sshd_config("/etc/ssh/sshd_config").MACs || "no MACs found"
  permitted_macs = %w{hmac-sha2-256 hmac-sha2-512}
  
  configured_macs.split(",").each do |entry|
    describe permitted_macs do
      it { should include entry }
    end
  end
  
  describe.one do
    describe file("/etc/sysconfig/prelink") do
      its("content") { should match(/^[\s]*PRELINKING=no[\s]*/) }
    end
    describe package("prelink") do
      it { should_not be_installed }
    end
  end
  
  describe package("dracut-fips") do
    it { should be_installed }
  end
  
  supported_rhel7_versions = %w{7.2 7.3 7.4 7.5 7.6}
  
  describe supported_rhel7_versions do
    it { should include os.release }
  end
  
  grub_file = file('/sys/firmware/efi').directory? ? "/boot/efi/EFI/redhat/grub.cfg" : "/boot/grub2/grub.cfg"
  describe file(grub_file) do
    its("content") { should match(/^\s*linux(?:[^#\n]*)\/vmlinuz([^#\n]*)/) }
    its("content") { should match(/^(.* )?fips=1( .*)?$/) }
  end
  
  describe file("/proc/sys/crypto/fips_enabled") do
    its("content") { should match(/^1$/) }
  end
  
  if file("/etc/default/grub").exist?
    grub_cmdline_default = file("/etc/default/grub").content.match(/\s*GRUB_CMDLINE_LINUX="(.*)"$/) || ["","GRUB_CMDLINE_LINUX option does not exist"]
  
    describe grub_cmdline_default[1] do
      it { should match(/^(.* )?fips=1( .*)?$/) }
    end
  
    grub_cmdline_default = file("/etc/default/grub").content.match(/^\s*GRUB_CMDLINE_LINUX_DEFAULT="(.*)"$/) || ["","GRUB_CMDLINE_LINUX_DEFAULT option does not exist"]
    
    if grub_cmdline_default = file("/etc/default/grub").content.match(/^\s*GRUB_CMDLINE_LINUX_DEFAULT="(.*)"$/)
    describe grub_cmdline_default[1] do
      it { should match(/^(.* )?fips=1( .*)?$/) }
    end
   end
  else
    describe file("/etc/default/grub") do
      skip("/etc/default/grub does not exist on this system")
    end   
  end
end
