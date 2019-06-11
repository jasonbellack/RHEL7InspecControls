control "xccdf_mil.disa.stig_rule_SV-86891r3_rule" do
  title "The Red Hat Enterprise Linux operating system must be configured so that the SSH daemon does not allow compression or only allows compression after successful authentication."
  desc  "
    Vulnerability Discussion: If compression is allowed in an SSH connection prior to authentication, vulnerabilities in the compression software could result in compromise of the system from an unauthenticated connection, potentially with root privileges.
    
    Documentable: false
    
  "
  impact 0.5
  only_if { package("openssh-server").installed? }
  describe sshd_config("/etc/ssh/sshd_config") do
    its("Compression") { should_not be_nil }
    its("Compression") { should match(/^(no|delayed)$/) }
  end
end
