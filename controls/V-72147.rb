control "xccdf_mil.disa.stig_rule_SV-86771r3_rule" do
  title "The Red Hat Enterprise Linux operating system must generate audit records for all successful account access events."
  desc  "
    Vulnerability Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
    
    Audit records can be generated from various components within the information system (e.g., module or policy filter).
    
    Satisfies: SRG-OS-000392-GPOS-00172, SRG-OS-000470-GPOS-00214, SRG-OS-000473-GPOS-00218
    
    Documentable: false
    
  "
  impact 0.5
  describe.one do
    files = command("find /etc/audit/rules.d -type f -regex .\\*/.\\*\\\\.rules\\$").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\-w\s+\/var\/log\/lastlog\s+\-p\s+\b([rx]*w[rx]*a[rx]*|[rx]*a[rx]*w[rx]*)\b\s+(-k[\s]+|-F[\s]+key=)[-\w]+\s*$/ } do
      it { should_not be_empty }
    end
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^\-w\s+\/var\/log\/lastlog\s+\-p\s+\b([rx]*w[rx]*a[rx]*|[rx]*a[rx]*w[rx]*)\b\s+(-k[\s]+|-F[\s]+key=)[-\w]+\s*$/) }
    end
  end
end
