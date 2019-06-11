control "xccdf_mil.disa.stig_rule_SV-86555r2_rule" do
  title "The Red Hat Enterprise Linux operating system must be configured so that existing passwords are restricted to a 60-day maximum lifetime."
  desc  "
    Vulnerability Discussion: Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed periodically. If the operating system does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the operating system passwords could be compromised.
    
    Documentable: false
    
  "
  impact 0.5
  interactive_users = users.where { uid.to_i >= 1000 }.usernames
  anonymous_users = users.where { [65534, 65535, 4294967294, 4294967295].include? uid.to_i }.usernames
  describe.one do
    describe interactive_users do
      it { should be_empty }
    end
    describe shadow.where { !anonymous_users.include?(user) && interactive_users.include?(user) && (max_days.to_i > 60 || max_days.to_i < 1 || max_days.nil?) } do
      its('raw_data') { should be_empty }
    end
  end
end
