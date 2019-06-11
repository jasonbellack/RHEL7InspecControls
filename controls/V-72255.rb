control "xccdf_mil.disa.stig_rule_SV-86879r2_rule" do
  title "The Red Hat Enterprise Linux operating system must be configured so that the SSH public host key files have mode 0644 or less permissive."
  desc  "
    Vulnerability Discussion: If a public host key file is modified by an unauthorized user, the SSH service may be compromised.
    
    Documentable: false
    
  "
  impact 0.5
  describe.one do
    describe package("openssh-server") do
      it { should_not be_installed }
    end
    describe command("find /etc/ssh/*_key.pub -type f -perm -0644") do
      its("stdout") { should_not be_empty }
    end
  end
end
