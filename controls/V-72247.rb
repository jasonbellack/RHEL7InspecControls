control "xccdf_mil.disa.stig_rule_SV-86871r3_rule" do
  title "The Red Hat Enterprise Linux operating system must not permit direct logons to the root account using remote access via SSH."
  desc  "
    Vulnerability Discussion: Even though the communications channel may be encrypted, an additional layer of security is gained by extending the policy of not logging on directly as root. In addition, logging on with a user-specific account provides individual accountability of actions performed on the system.
    
    Documentable: false
    
  "
  impact 0.5
  only_if { package("openssh-server").installed? }
  describe sshd_config("/etc/ssh/sshd_config") do
    its("PermitRootLogin") { should_not be_nil }
    its("PermitRootLogin") { should eq "no" }
  end
end
