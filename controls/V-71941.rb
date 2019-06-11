control "xccdf_mil.disa.stig_rule_SV-86565r2_rule" do
  title "The Red Hat Enterprise Linux operating system must disable account identifiers (individuals, groups, roles, and devices) if the password expires."
  desc  "
    Vulnerability Discussion: Inactive identifiers pose a risk to systems and applications because attackers may exploit an inactive identifier and potentially obtain undetected access to the system. Owners of inactive accounts will not notice if unauthorized access to their user account has been obtained.
    
    Operating systems need to track periods of inactivity and disable application identifiers after zero days of inactivity.
    
    Documentable: false
    
  "
  impact 0.5
  describe file("/etc/default/useradd") do
    its("content") { should match(/^\s*INACTIVE\s*=\s*(\d+)\s*$/) }
  end
  file("/etc/default/useradd").content.to_s.scan(/^\s*INACTIVE\s*=\s*(\d+)\s*$/).flatten.each do |entry|
    describe entry do
      it { should cmp <= 0 }
    end
  end
  file("/etc/default/useradd").content.to_s.scan(/^\s*INACTIVE\s*=\s*(\d+)\s*$/).flatten.each do |entry|
    describe entry do
      it { should cmp > -1 }
    end
  end
end
