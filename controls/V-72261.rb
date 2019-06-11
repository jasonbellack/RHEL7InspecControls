control "xccdf_mil.disa.stig_rule_SV-86885r3_rule" do
  title "The Red Hat Enterprise Linux operating system must be configured so that the SSH daemon does not permit Kerberos authentication unless needed."
  desc  "
    Vulnerability Discussion: Kerberos authentication for SSH is often implemented using Generic Security Service Application Program Interface (GSSAPI). If Kerberos is enabled through SSH, the SSH daemon provides a means of access to the system's Kerberos implementation. Vulnerabilities in the system's Kerberos implementation may then be subject to exploitation. To reduce the attack surface of the system, the Kerberos authentication mechanism within SSH must be disabled for systems not using this capability.
    
    Documentable: false
    
  "
  impact 0.5
  only_if { package("openssh-server").installed? }
  describe sshd_config("/etc/ssh/sshd_config") do
    its("KerberosAuthentication") { should_not be_nil }
    its("KerberosAuthentication") { should eq "no" }
  end
end
