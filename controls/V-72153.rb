control "xccdf_mil.disa.stig_rule_SV-86777r4_rule" do
  title "The Red Hat Enterprise Linux operating system must audit all uses of the gpasswd command."
  desc  "
    Vulnerability Discussion: Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.
    
    At a minimum, the organization must audit the full-text recording of privileged password commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.
    
    Satisfies: SRG-OS-000042-GPOS-00020, SRG-OS-000392-GPOS-00172, SRG-OS-000471-GPOS-00215
    
    Documentable: false
    
  "
  impact 0.5
  describe.one do
    files = command("find /etc/audit/rules.d -type f -regex '.*\.rules'$").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^[\s]*-a[\s]+always,exit[\s]+-F[\s]+path=\/usr\/bin\/gpasswd[\s]+-F[\s]+perm=([rwa]*x[rwa]*)[\s]+-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$/ } do
      it { should_not be_empty }
    end
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^[\s]*-a[\s]+always,exit[\s]+-F[\s]+path=\/usr\/bin\/gpasswd[\s]+-F[\s]+perm=([rwa]*x[rwa]*)[\s]+-F[\s]+auid>=1000[\s]+-F[\s]+auid!=4294967295[\s]+(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$/) }
    end
  end
end
