control "xccdf_mil.disa.stig_rule_SV-86863r4_rule" do
  title "The Red Hat Enterprise Linux operating system must be configured so that the SSH daemon does not allow authentication using RSA rhosts authentication."
  desc  "
    Vulnerability Discussion: Configuring this setting for the SSH daemon provides additional assurance that remote logon via SSH will require a password, even in the event of misconfiguration elsewhere.
    
    Documentable: false
    
  "
  impact 0.5
  only_if { package('openssh-server').installed? }
  describe.one do
    describe package('openssh-server') do
      its('version') { should be >= '7.4' }
    end
    rhosts_rsa_authentication = file("/etc/ssh/sshd_config").content.to_s.scan(/^[\s]*(?i)RhostsRSAAuthentication(?-i)[\s]+(\w+)[\s]*(?:|(?:#.*))?$/).flatten
    describe rhosts_rsa_authentication.reject { |x| x == "no" } do
      it { should be_empty }
    end
  end
end
