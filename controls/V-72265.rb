control "xccdf_mil.disa.stig_rule_SV-86889r3_rule" do
  title "The Red Hat Enterprise Linux operating system must be configured so that the SSH daemon uses privilege separation."
  desc  "
    Vulnerability Discussion: SSH daemon privilege separation causes the SSH process to drop root privileges when not needed, which would decrease the impact of software vulnerabilities in the unprivileged section.
    
    Documentable: false
    
  "
  impact 0.5
  only_if { package("openssh-server").installed? }
  describe sshd_config("/etc/ssh/sshd_config") do
    its("UsePrivilegeSeparation") { should_not be_nil }
  end
  describe.one do
    describe sshd_config("/etc/ssh/sshd_config") do
      its("UsePrivilegeSeparation") { should eq "sandbox" }
    end
    describe sshd_config("/etc/ssh/sshd_config") do
      its("UsePrivilegeSeparation") { should eq "yes" }
    end
  end
end
