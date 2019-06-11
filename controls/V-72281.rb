control "xccdf_mil.disa.stig_rule_SV-86905r2_rule" do
  title "For Red Hat Enterprise Linux operating systems using DNS resolution, at least two name servers must be configured."
  desc  "
    Vulnerability Discussion: To provide availability for name resolution services, multiple redundant name servers are mandated. A failure in name resolution could lead to the failure of security functions requiring name resolution, which may include time synchronization, centralized authentication, and remote system logging.
    
    Documentable: false
    
  "
  impact 0.1
  if file("/etc/nsswitch.conf").content =~ /^\s*hosts:[ \t]\s.*dns(\s.*|$)/
    describe file("/etc/resolv.conf") do
      its("content") { should match(/^\s*nameserver\s(.*)$/) }
    end
    describe file("/etc/resolv.conf").content.to_s.scan(/^\s*nameserver\s(.*)$/) do
      its("length") { should cmp >= 2 }
    end
  else
    describe file("/etc/resolv.conf") do
      it { should exist }
      its("length") { should eq 0 }
    end
  end
end
