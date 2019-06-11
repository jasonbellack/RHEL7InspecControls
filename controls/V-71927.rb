control "xccdf_mil.disa.stig_rule_SV-86551r2_rule" do
  title "The Red Hat Enterprise Linux operating system must be configured so that passwords are restricted to a 24 hours/1 day minimum lifetime."
  desc  "
    Vulnerability Discussion: Enforcing a minimum password lifetime helps to prevent repeated password changes to defeat the password reuse or history enforcement requirement. If users are allowed to immediately and continually change their password, the password could be repeatedly changed in a short period of time to defeat the organization's policy regarding password reuse.
    
    Documentable: false
    
  "
  impact 0.5
  passwd.where { uid.to_i >= 1000 && ![65534, 65535, 4294967294, 4294967295].include?(uid.to_i) }.users.each do |entry|
    describe shadow.where { user == entry } do
      its('min_days.first.to_i') { should >= 1 }
      its('min_days.first') { should_not be_nil }
    end
  end
end
