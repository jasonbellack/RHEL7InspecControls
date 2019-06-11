control "xccdf_mil.disa.stig_rule_SV-86887r3_rule" do
  title "The Red Hat Enterprise Linux operating system must be configured so that the SSH daemon performs strict mode checking of home directory configuration files."
  desc  "
    Vulnerability Discussion: If other users have access to modify user-specific SSH configuration files, they may be able to log on to the system as another user.
    
    Documentable: false
    
  "
  impact 0.5
  only_if { package("openssh-server").installed? }
  describe sshd_config("/etc/ssh/sshd_config") do
    its("StrictModes") { should_not be_nil }
    its("StrictModes") { should eq "yes" }
  end
end
