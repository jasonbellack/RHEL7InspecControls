control "xccdf_mil.disa.stig_rule_SV-86759r4_rule" do
  title "The Red Hat Enterprise Linux operating system must audit all uses of the semanage command."
  desc  "
    Vulnerability Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
    
    Audit records can be generated from various components within the information system (e.g., module or policy filter).
    
    Satisfies: SRG-OS-000392-GPOS-00172, SRG-OS-000463-GPOS-00207, SRG-OS-000465-GPOS-00209
    
    Documentable: false
    
  "
  impact 0.5
  describe.one do
    files = command('find /etc/audit/rules.d -type f -regex ".*\.rules$"').stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^[\s]*-a[\s]+always,exit[\s]+-F[\s]+path=\/usr\/sbin\/setfiles[\s]+-F[\s]+auid\>\=1000[\s]+-F[\s]+auid\!\=4294967295[\s]+-k[\s]+privileged-priv_change[\s]*$/ } do
      it { should_not be_empty }
    end
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^[\s]*-a[\s]+always,exit[\s]+-F[\s]+path=\/usr\/sbin\/setfiles[\s]+-F[\s]+auid\>\=1000[\s]+-F[\s]+auid\!\=4294967295[\s]+-k[\s]+privileged-priv_change[\s]*$/) }
    end
  end
end
