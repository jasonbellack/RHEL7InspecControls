control "xccdf_mil.disa.stig_rule_SV-86609r2_rule" do
  title "The Red Hat Enterprise Linux operating system must disable the file system automounter unless required."
  desc  "
    Vulnerability Discussion: Automatically mounting file systems permits easy introduction of unknown devices, thereby facilitating malicious activity.
    
    Satisfies: SRG-OS-000114-GPOS-00059, SRG-OS-000378-GPOS-00163, SRG-OS-000480-GPOS-00227
    
    Documentable: false
    
  "
  impact 0.5
  processes(/^(\/usr)?\/sbin\/automount.*/).where { pid > 1 }.entries.each do |entry|
    describe entry.label.to_s.split(':')[2] do
      it { should_not exist }
    end
  end
end
