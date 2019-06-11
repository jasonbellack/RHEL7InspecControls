control "xccdf_mil.disa.stig_rule_SV-86715r2_rule" do
  title "The Red Hat Enterprise Linux operating system must immediately notify the System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) via email when the threshold for the repository maximum audit record storage capacity is reached."
  desc  "
    Vulnerability Discussion: If security personnel are not notified immediately when the threshold for the repository maximum audit record storage capacity is reached, they are unable to expand the audit record storage capacity before records are lost.
    
    Documentable: false
    
  "
  impact 0.5
  describe file("/etc/audit/auditd.conf") do
    its("content") { should match(/^[ ]*space_left_action[ ]+=[ ]+([^ ]*)[ ]*$/mi) }
  end
  file("/etc/audit/auditd.conf").content.to_s.scan(/^[ ]*space_left_action[ ]+=[ ]+([^ ]*)[ ]*$/mi).flatten.each do |entry|
    describe entry do
      it { should match(/^[Ee][Mm][Aa][Ii][Ll]$/) }
    end
  end
end
