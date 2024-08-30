#!/bin/bash
# script to transform MISP galaxies to STIX bundle format for import into STIX compatible platforms like OpenCTI
# This script parses threat actors and converts them into stix "intrusion sets".
######################################################
#
# TODO: Combine these with the tools/malwares referenced
# TODO: Splitt out those intrusion sets named "operation*" into campaigns (?) since it seems more likely they campaign descriptions rather than intrusion sets.
#
#

# Since we run this manually at the moment we need something to parse
# Start with getting an input (file) to parse
if [ -z $1 ]
then 
echo "USAGE: $0 <misp-file>"
exit 1
fi

####################### Start parsing data
##### Creating our source country locations and relationships with Intrusion Sets 
#
# This is a cleaner way of getting source locations / originates_from, however it is commented out since its a duplicate of the dirtyer way further down
# From where do our intrusion sets originate ?
# We need to create one stix location as the source country by intrusion set, where this is present in the data.
# 

#

cat $1 | sed 's/cfr-suspected-victims/victims/g' | jq '.values[] as $value | if $value.meta.country then {type: "location", spec_version: "2.1", created: "'$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")'", modified: "'$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")'", id: "null", country: $value.meta.country} else empty end' | jq -s 'unique_by(.country)' | jq -c '.[]' | sed -E 's/country\":\"([^,]+),[^,]+/country\":\"\1\"}/g' > source_locations.tmp
# Extract countries and put the source locations into temp file
grep -vi "country\":\"\"" source_locations.tmp > source_locations2.tmp
jq '.country' source_locations2.tmp | sed 's/\"//g' > sources.tmp
# After this we need to create a uuid mapping between source location and id
while IFS=$'\n' read -r line; do echo "$line:`uuidgen`"; done < sources.tmp > source_id.map

# next step is to add the uuid to the source ( orginiates_from ) country location 
declare -A id_map

# Read file targets_id.map and populate the associative array with country names and id-strings
while IFS=: read -r country id_string; do
    id_map["$country"]="$id_string"
done < source_id.map

# Iterate over file B and replace the pattern "null" after "id": with the id-string
while IFS=$'\n' read -r line; do
    for country in "${!id_map[@]}"; do
        # Use the country name as a placeholder to find the correct id-string
        if [[ "$line" == *"$country"* ]]; then
            # Replace the pattern "null" after "id": with the id-string
            line=$(echo "$line" | sed "s/\"id\":\"null\"/\"id\":\"location--${id_map[$country]}\"/")
        fi
    done
    echo "$line"
done < source_locations.tmp > source_locations.json

# Now we need to create a stix relationship between the location and the intrusion set(s).

cat $1 | jq '.values[] as $value | if $value.meta.country then {type: "relationship", spec_version: "2.1", id: "relationship--XXX", created: "'$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")'", modified: "'$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")'", relationship_type: "originates-from", source_ref: "intrusion-set--\($value.uuid)", target_ref: $value.meta.country} else empty end' | jq -c '.' > source_relation.tmp

# now we need to replace relationship-XXX with relationship-`uuidgen`
while IFS= read -r line; do
echo "${line//XXX/$(uuidgen)}"
done < source_relation.tmp > s_rel.tmp

# Mapping the relationship object to the target location(s)
while IFS=: read -r country id_string; do
    id_map["$country"]="$id_string"
done < source_id.map

# Add the mapping by replacing country with country id
while IFS=$'\n' read -r line; do
    for country in "${!id_map[@]}"; do
        line=${line//"$country"/"location--${id_map[$country]}"}
    done
    echo "$line"
done < s_rel.tmp > source_relation.json

##### Creating our targeted country locations and relationshops with Intrusion Sets
#
# We need to create a stix location for each of the countries present in the file marked as targets
cat $1 | sed 's/cfr-suspected-victims/country_targets/g' | jq '.values[] as $value | if $value.meta.country_targets then {type: "location", spec_version: "2.1", created: "'$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")'", modified: "'$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")'", country: $value.meta.country_targets[], id: "null"} else empty end'  | jq -s 'unique_by(.country)' | jq -c '.[]' > targets.tmp
#


# since the "targets" mention in the misp file contains a mix between companies, organisations and countries we need to filter/remove those that does not correspond to a country
grep -f test_country.list targets.tmp > target_locations.tmp
# generate the target list
jq '.country' target_locations.tmp | sed 's/\"//g' > targets.list

# After this we need to create a uuid mapping between country and id
while IFS=$'\n' read -r line; do echo "$line:`uuidgen`"; done < targets.list > targets_id.map


# next step is to add the uuid to the targeted country location 
declare -A id_map

# Read file targets_id.map and populate the associative array with country names and id-strings
while IFS=: read -r country id_string; do
    id_map["$country"]="$id_string"
done < targets_id.map

# Iterate over file B and replace the pattern "null" after "id": with the id-string
while IFS=$'\n' read -r line; do
    for country in "${!id_map[@]}"; do
        # Use the country name as a placeholder to find the correct id-string
        if [[ "$line" == *"$country"* ]]; then
            # Replace the pattern "null" after "id": with the id-string
            line=$(echo "$line" | sed "s/\"id\":\"null\"/\"id\":\"location--${id_map[$country]}\"/")
        fi
    done
    echo "$line"
done < target_locations.tmp > target_locations.json


# create the relationships object
cat $1 | sed 's/cfr-suspected-victims/country_targets/g'  | jq '.values[] as $value | if $value.meta.country_targets then {type: "relationship", spec_version: "2.1", id: "relationship--XXX", created: "'$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")'", modified: "'$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")'", relationship_type: "targets", source_ref: "intrusion-set--\($value.uuid)", target_ref: $value.meta.country_targets[]} else empty end' | jq -c '.' > target_relation.tmp
# Filter out none-country locations
grep -f test_country.list target_relation.tmp > target_relations.tmp

# now we need to replace relationship-XXX with relationship-`uuidgen`
while IFS= read -r line; do
echo "${line//XXX/$(uuidgen)}"
done < target_relations.tmp > rel.tmp

# Mapping the relationship object to the target location(s)
while IFS=: read -r country id_string; do
    id_map["$country"]="$id_string"
done < targets_id.map

# Add the mapping by replacing country with country id
while IFS=$'\n' read -r line; do
    for country in "${!id_map[@]}"; do
        line=${line//"$country"/"location--${id_map[$country]}"}
    done
    echo "$line"
done < rel.tmp > target_relation.json

################
##### Intrusion Sets also targets sectors
#
# Get all the uniq sectors
# Creating the main sector identity bundle
cat $1 | sed 's/cfr-target-category/sector/g' | jq '.values[] as $value | if $value.meta.sector then {type: "identity", spec_version: "2.1", created: "'$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")'", modified: "'$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")'",identity_class: "class", id: "null", name: $value.meta.sector[]} else empty end' | jq -s 'unique_by(.name)' | jq -c '.[]' > sector_identity.tmp
# since sector targets is in booth target-category and in targeted-sector we need to this twice
cat $1 | sed 's/targeted-sector/sector/g' | jq '.values[] as $value | if $value.meta.sector then {type: "identity", spec_version: "2.1", created: "'$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")'", modified: "'$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")'",identity_class: "class", id: "null", name: $value.meta.sector[]} else empty end' | jq -s 'unique_by(.name)' | jq -c '.[]' > sector_identity2.tmp

#Generate uniq ids per sector
# filter out the sector names into tmp file
cat sector_identity.tmp | jq '.name' | sed "s/\"//g" > sectors.list
cat sector_identity2.tmp | jq '.name' | sed "s/\"//g" > sectors2.list
# merge sector list(s)
cat sectors.list sectors2.list | sort |uniq > sector.list
#
# Merge both sector identity bundles
cat sector_identity.tmp sector_identity2.tmp | sort | uniq > sector_identity.tmp
#
# Iterate and generate uuid for each sector
while IFS=$'\n' read -r line;  do echo "$line":`uuidgen`; done < sector.list > sector_ids.map

# next step is to add the uuid to the targeted country location 
declare -A id_map

# Read file targets_id.map and populate the associative array with country names and id-strings
while IFS=: read -r sector id_string; do
    id_map["$sector"]="$id_string"
done < sector_ids.map

# Iterate over file B and replace the pattern "null" after "id": with the id-string
while IFS=$'\n' read -r line; do
    for sector in "${!id_map[@]}"; do
        # Use the country name as a placeholder to find the correct id-string
        if [[ "$line" == *"$sector"* ]]; then
            # Replace the pattern "null" after "id": with the id-string
            line=$(echo "$line" | sed "s/\"id\":\"null\"/\"id\":\"identity--${id_map[$sector]}\"/")
        fi
    done
    echo "$line"
done < sector_identity.tmp > sector_identity.json


# Create the relationship between the targetes sectors and intrusion-set(s)
cat $1 | sed 's/cfr-target-category/sector/g'  | jq '.values[] as $value | if $value.meta.sector then {type: "relationship", spec_version: "2.1", id: "relationship--XXX", created: "'$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")'", modified: "'$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")'", relationship_type: "targets", source_ref: "intrusion-set--\($value.uuid)", target_ref: $value.meta.sector[]} else empty end' | jq -c '.' > sector_relation.tmp
# since sector targets is in booth target-category and in targeted-sector we need to this twice
cat $1 | sed 's/targeted-sector/sector/g'  | jq '.values[] as $value | if $value.meta.sector then {type: "relationship", spec_version: "2.1", id: "relationship--XXX", created: "'$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")'", modified: "'$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")'", relationship_type: "targets", source_ref: "intrusion-set--\($value.uuid)", target_ref: $value.meta.sector[]} else empty end' | jq -c '.' > sector_relation2.tmp

cat sector_relation.tmp sector_relation2.tmp >> sector_relations.tmp


# now we need to replace relationship-XXX with relationship-`uuidgen`
while IFS= read -r line; do
echo "${line//XXX/$(uuidgen)}"
done < sector_relations.tmp > sector_mapping.tmp

# Mapping the relationship object to the sector
while IFS=: read -r sector id_string; do
    id_map["$sector"]="$id_string"
done < sector_ids.map

# Add the mapping by replacing sector with sector id
while IFS=$'\n' read -r line; do
    for sector in "${!id_map[@]}"; do
        line=${line//"$sector"/"identity--${id_map[$sector]}"}
    done
    echo "$line"
done < sector_mapping.tmp > sector_relation.json

##########################
######## Bringing it all together
#
# so far we have:
#  source_locations.json = contains the orginates_from location in stix format
#  source_relation.json = contains the stix relationship mapped between originates from and intrusion set(s)
#  target_locations.json = contains all the stix location 
#  target_relation.json = contains the stix relation mapped between location and intrusion set(s)
#  sector_identity.json = contains the stix identity for each sector targeted
#  sector_relation.json = contains the stix relation mapped between sectors and intrusion set(s)
#
# Add stix bundle header
echo "{
\"type\": \"bundle\",
\"id\": \"bundle--`uuidgen`\",
\"objects\": [" > tidal_intrusion_sets.json

# Get all the actors
# create bundle with name, aliases, description, source country and motiviation 
# TODO: Can i itterate over the key:value and objects instead of needing to print a range - that produces null values ?
#cat $1 | jq '.values[] as $value
#| {spec_verion: "2.1",created: "'$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")'", modified: "'$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")'", type: "intrusion-set", id: "intrusion-set--\($value.uuid)", name: $value.value, description: $value.description, motivation: $value.meta.motivation, alias: $value.meta.synonyms, external_references: [{source_name: "Misp", url: $value.meta.refs[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18.19,20]}]},
# {type: "location", spec_version: "2.1", created: "'$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")'", modified: "'$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")'", id: "location--\($value.uuid)", country: $value.meta.country}, {type: "relationship", spec_version: "2.1", id: "relationship--\($value.uuid)", created: "'$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")'", modified: "'$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")'", relationship_type: "originates-from", source_ref: "intrusion-set--\($value.uuid)", target_ref: "location--\($value.uuid)"}' > intrusion_sets.tmp
cat $1 | sed 's/cfr-type-of-incident/goal/g' | jq '.values[] as $value | {spec_verion: "2.1",created: "'$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")'", modified: "'$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")'", type: "intrusion-set", id: "intrusion-set--\($value.uuid)", name: $value.value, description: $value.description, goals: $value.meta.goal, aliases: $value.meta.synonyms, external_references: [{source_name: "MISP", url: $value.meta.refs[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18.19,20]}]}'| jq -c '.' | sed -E 's/,\{\"source_name\":\"MISP\",\"url\":null\}//g' > intrusion_sets.tmp

#
# The misp galaxy files could contain multiple names/values in the actor field, we need to strip those out 
# while IFS=$'\n' read -r line; do echo "$line" | sed -E 's/name\":\"([^,]+),[[:space:]][^,]+/name\":\"\1\"/g'; done < test.tmp

while IFS=$'\n' read -r line; do echo "$line" | sed -E 's/"name\":\"([^\,]+),[[:space:]][^,].*\",\"description/"name":"\1","description/g'; done < intrusion_sets.tmp > intrusion_sets2.tmp

#
# In atleast one case there is a space \d+ in one of the uuids provided - That something we need to take into account
#
# Appending targets to the intrusion set file
cat source_locations.json >> intrusion_sets2.tmp
cat source_relation.json >> intrusion_sets2.tmp
cat target_locations.json >> intrusion_sets2.tmp
cat target_relation.json >> intrusion_sets2.tmp
cat sector_identity.json >> intrusion_sets2.tmp
cat sector_relation.json >> intrusion_sets2.tmp

# Correcting the json structure
cat intrusion_sets2.tmp | sed -E ':l;N;$!bl; s/}\n\{/},\n\{/g' >> intrusion_sets.json
# dirty fix of a bug
cat intrusion_sets.json | sed 's/, Administration//g' > misp_intrustion_sets.stix

# add the closing json things
echo "]
}" >> misp_intrusion_sets.stix


 