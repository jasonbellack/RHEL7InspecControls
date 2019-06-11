
control "xccdf_mil.disa.stig_rule_SV-87815r3_rule" do
  title "The Red Hat Enterprise Linux operating system must be configured so that the audit system takes appropriate action when there is an error sending audit records to a remote system."
  desc  "
    Vulnerability Discussion: Taking appropriate action when there is an error sending audit records to a remote system will minimize the possibility of losing audit records.
    
    Documentable: false
    
  "
  impact 0.5
  describe.one do
    files = command("find /etc/audisp/ -type f -regex \/.*\/audisp-remote\.conf$").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|execuable|archive/ || file(f).content !~ /^[\s]*network_failure_action[\s]=[\s](syslog|single|halt).*$/ } do
      it { should_not be_empty }
    end
    describe file("/etc/audisp/audisp-remote.conf") do
      its("content") { should match(/^[\s]*network_failure_action[\s]=[\s](syslog|single|halt).*$/) }
    end
  end
end
