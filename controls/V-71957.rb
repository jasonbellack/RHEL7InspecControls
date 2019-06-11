control "xccdf_mil.disa.stig_rule_SV-86581r3_rule" do
  title "The Red Hat Enterprise Linux operating system must not allow users to override SSH environment variables."
  desc  "
    Vulnerability Discussion: Failure to restrict system access to authenticated users negatively impacts operating system security.
    
    Documentable: false
    
  "
  impact 0.5
  only_if { package("openssh-server").installed? }
  describe sshd_config("/etc/ssh/sshd_config") do
    its("PermitUserEnvironment") { should_not be_nil }
    its("PermitUserEnvironment") { should cmp "no" }
  end
end
