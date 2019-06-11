control "xccdf_mil.disa.stig_rule_SV-86627r2_rule" do
  title "The Red Hat Enterprise Linux operating system must be configured so that all Group Identifiers (GIDs) referenced in the /etc/passwd file are defined in the /etc/group file."
  desc  "
    Vulnerability Discussion: If a user is assigned the GID of a group not existing on the system, and a group with the GID is subsequently created, the user may have unintended rights to any files associated with the group.
    
    Documentable: false
    
  "
  impact 0.1
  existing_group_gids = groups.gids
  describe passwd.where { !existing_group_gids.include?(gid.to_i)  } do
    its('raw_data') { should be_empty }
  end
end
