control "xccdf_mil.disa.stig_rule_SV-86787r5_rule" do
  title "The Red Hat Enterprise Linux operating system must audit all uses of the sudoers file and all files in the /etc/sudoers.d/ directory."
  desc  "
    Vulnerability Discussion: Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.
    
    At a minimum, the organization must audit the full-text recording of privileged access commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.
    
    Satisfies: SRG-OS-000037-GPOS-00015, SRG-OS-000042-GPOS-00020, SRG-OS-000392-GPOS-00172, SRG-OS-000462-GPOS-00206, SRG-OS-000471-GPOS-00215
    
    Documentable: false
    
  "
  impact 0.5
  describe.one do
    files = command("find /etc/audit/rules.d -type f -regex '\.rules$'").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\-w[\s]+\/etc\/sudoers[\s]+\-p[\s]+\b([rx]*w[rx]*a[rx]*|[rx]*a[rx]*w[rx]*)\b[\s]+(-k[\s]+|-F[\s]+key=)[-\w]+[\s]*$/ || file(f).content !~ /^\-w[\s]+\/etc\/sudoers\.d\/?[\s]+\-p[\s]+\b([rx]*w[rx]*a[rx]*|[rx]*a[rx]*w[rx]*)\b[\s]+(-k[\s]+|-F[\s]+key=)[-\w]+[\s]*$/ } do
      it { should_not be_empty }
    end
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^\-w[\s]+\/etc\/sudoers[\s]+\-p[\s]+\b([rx]*w[rx]*a[rx]*|[rx]*a[rx]*w[rx]*)\b[\s]+(-k[\s]+|-F[\s]+key=)[-\w]+[\s]*$/) }
      its("content") { should match(/^\-w[\s]+\/etc\/sudoers\.d\/?[\s]+\-p[\s]+\b([rx]*w[rx]*a[rx]*|[rx]*a[rx]*w[rx]*)\b[\s]+(-k[\s]+|-F[\s]+key=)[-\w]+[\s]*$/) }
    end
  end
end
