control "xccdf_mil.disa.stig_rule_SV-86679r2_rule" do
  title "The Red Hat Enterprise Linux operating system must be configured so that the cron.allow file, if it exists, is group-owned by root."
  desc  "
    Vulnerability Discussion: If the group owner of the \"cron.allow\" file is not set to root, sensitive information could be viewed or edited by unauthorized users.
    
    Documentable: false
    
  "
  impact 0.5
  describe file("/etc/cron.allow") do
    it { should exist }
  end
  describe file("/etc/cron.allow") do
    its("gid") { should cmp 0 }
  end
end
