control "xccdf_mil.disa.stig_rule_SV-87813r2_rule" do
  title "The Red Hat Enterprise Linux operating system must prevent binary files from being executed on file systems that are being imported via Network File System (NFS)."
  desc  "
    Vulnerability Discussion: The \"noexec\" mount option causes the system to not execute binary files. This option must be used for mounting any file system not containing approved binary files as they may be incompatible. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.
    
    Documentable: false
    
  "
  impact 0.5
  describe file("/etc/fstab") do
    its("content") { should match(/^\s*\[?[\.\w:-]+\]?:[\/\w-]+\s+[\/\w-]+\s+nfs[4]?\s+(.*)$/) }
  end
  file("/etc/fstab").content.to_s.scan(/^\s*\[?[\.\w:-]+\]?:[\/\w-]+\s+[\/\w-]+\s+nfs[4]?\s+(.*)$/).flatten.each do |entry|
    describe entry do
      it { should match(/^.*noexec.*$/) }
    end
  end
  describe file("/etc/mtab") do
    its("content") { should match(/^\s*\[?[\.\w:-]+\]?:[\/\w-]+\s+[\/\w-]+\s+nfs[4]?\s+(.*)$/) }
  end
  file("/etc/mtab").content.to_s.scan(/^\s*\[?[\.\w:-]+\]?:[\/\w-]+\s+[\/\w-]+\s+nfs[4]?\s+(.*)$/).flatten.each do |entry|
    describe entry do
      it { should match(/^.*noexec.*$/) }
    end
  end
end
