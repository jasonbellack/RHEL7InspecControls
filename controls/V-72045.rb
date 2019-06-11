control "xccdf_mil.disa.stig_rule_SV-86669r2_rule" do
  title "The Red Hat Enterprise Linux operating system must prevent files with the setuid and setgid bit set from being executed on file systems that are being imported via Network File System (NFS)."
  desc  "
    Vulnerability Discussion: The \"nosuid\" mount option causes the system to not execute \"setuid\" and \"setgid\" files with owner privileges. This option must be used for mounting any file system not containing approved \"setuid\" and \"setguid\" files. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.
    
    Documentable: false
    
  "
  impact 0.5
  describe filesystem('/') do 
    its('type') { should cmp 'xfs' }
  end    
  describe file("/etc/fstab") do
    its("content") { should match(/^\s*\[?[\.\w:-]+\]?:[\/\w-]+\s+[\/\w-]+\s+nfs[4]?\s+(.*)$/) }
  end
  file("/etc/fstab").content.to_s.scan(/^\s*\[?[\.\w:-]+\]?:[\/\w-]+\s+[\/\w-]+\s+nfs[4]?\s+(.*)$/).flatten.each do |entry|
    describe entry do
      it { should match(/^.*nosuid.*$/) }
    end
  end
  describe file("/etc/mtab") do
    its("content") { should match(/^\s*\[?[\.\w:-]+\]?:[\/\w-]+\s+[\/\w-]+\s+nfs[4]?\s+(.*)$/) }
  end
  file("/etc/mtab").content.to_s.scan(/^\s*\[?[\.\w:-]+\]?:[\/\w-]+\s+[\/\w-]+\s+nfs[4]?\s+(.*)$/).flatten.each do |entry|
    describe entry do
      it { should match(/^.*nosuid.*$/) }
    end
  end
end
