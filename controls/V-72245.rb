control "xccdf_mil.disa.stig_rule_SV-86867r3_rule" do
  title "The Red Hat Enterprise Linux operating system must be configured so that the SSH daemon does not allow authentication using rhosts authentication."
  desc  "
    Vulnerability Discussion: Configuring this setting for the SSH daemon provides additional assurance that remote logon via SSH will require a password, even in the event of misconfiguration elsewhere.
    
    Documentable: false
    
  "
  impact 0.5
  only_if { package("openssh-server").installed? }
  describe sshd_config("/etc/ssh/sshd_config") do
    its("PrintLastLog") { should_not be_nil }
    its("PrintLastLog") { should eq "yes" }
  end
end
