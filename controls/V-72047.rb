control "xccdf_mil.disa.stig_rule_SV-86671r4_rule" do
  title "The Red Hat Enterprise Linux operating system must be configured so that all world-writable directories are group-owned by root, sys, bin, or an application group."
  desc  "
    Vulnerability Discussion: If a world-writable directory has the sticky bit set and is not group-owned by a privileged Group Identifier (GID), unauthorized users may be able to modify files created by others.
    
    The only authorized public directories are those temporary directories supplied with the system or those designed to be temporary file repositories. The setting is normally reserved for directories used by the system and by users for temporary file storage, (e.g., /tmp), and for directories requiring global read/write access.
    
    Documentable: false
    
  "
  impact 0.5
  describe command("find / -type d -perm -00002 -user 1000 -user +1000 -xdev") do
    its("stdout") { should be_empty }
  end
end
