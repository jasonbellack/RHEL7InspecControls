control "xccdf_mil.disa.stig_rule_SV-86563r3_rule" do
  title "The Red Hat Enterprise Linux operating system must be configured so that the SSH daemon does not allow authentication using an empty password."
  desc  "
    Vulnerability Discussion: Configuring this setting for the SSH daemon provides additional assurance that remote logon via SSH will require a password, even in the event of misconfiguration elsewhere.
    
    Documentable: false
    
  "
  impact 1.0
  describe.one do
    describe package("openssh-server") do
      it { should_not be_installed }
    end
    describe file("/etc/ssh/sshd_config") do
      its("content") { should match(/^[\s]*PermitEmptyPasswords[ \t]+([^\s#]*)[ \t]*(?:|(?:#.*))?$/mi) }
    end
    file("/etc/ssh/sshd_config").content.to_s.scan(/^[\s]*PermitEmptyPasswords[ \t]+([^\s#]*)[ \t]*(?:|(?:#.*))?$/mi).flatten.each do |entry|
      describe entry do
        it { should match(/^(no|"no")$/) }
      end
    end
  end
end
