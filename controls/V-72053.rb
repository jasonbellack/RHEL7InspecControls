control "xccdf_mil.disa.stig_rule_SV-86677r3_rule" do
  title "The Red Hat Enterprise Linux operating system must be configured so that the cron.allow file, if it exists, is owned by root."
  desc  "
    Vulnerability Discussion: If the owner of the \"cron.allow\" file is not set to root, the possibility exists for an unauthorized user to view or to edit sensitive information.
    
    Documentable: false
    
  "
  impact 0.5
  describe file("/etc/cron.allow") do
    it { should exist }
  end
  describe file("/etc/cron.allow") do
    its("uid") { should cmp 0 }
  end
end
