control "xccdf_mil.disa.stig_rule_SV-86883r3_rule" do
  title "The Red Hat Enterprise Linux operating system must be configured so that the SSH daemon does not permit Generic Security Service Application Program Interface (GSSAPI) authentication unless needed."
  desc  "
    Vulnerability Discussion: GSSAPI authentication is used to provide additional authentication mechanisms to applications. Allowing GSSAPI authentication through SSH exposes the system's GSSAPI to remote hosts, increasing the attack surface of the system. GSSAPI authentication must be disabled unless needed.
    
    Documentable: false
    
  "
  impact 0.5
  only_if { package("openssh-server").installed? }
  describe sshd_config("/etc/ssh/sshd_config") do
    its("GSSAPIAuthentication") { should_not be_nil }
    its("GSSAPIAuthentication") { should eq "no" }
  end
end

