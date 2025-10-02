# Copyright 2025 HTCondor Team, Computer Sciences Department,
# University of Wisconsin-Madison, WI.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from collections import OrderedDict

# MAX_KEYWORD_LEN is the value used for ignore_above
MAX_KEYWORD_LEN = 32766

# Attributes to be used in all projections to condor_history
REQUIRED_ATTRS = {
    "ClusterId",
    "CompletionDate",
    "EnteredCurrentStatus",
    "EpochWriteDate",
    "GlobalJobId",
    "JobStatus",
    "JobUniverse",
    "LastRemoteHost",
    "MyType",
    "ProcId",
    "RemoteHost",
}

# Attributes (in order) which should be used as a timestamp
TIMESTAMP_ATTRS = [
    "EpochWriteDate",
    "CompletionDate",
    "EnteredCurrentStatus",
]

# Attributes (in order) which should be used to unique identify a job/epoch
DOC_ID_ATTRS = [
    "GlobalJobId",
    "RecordTime",  # This is a derived timestamp that will always be available
]

# INDEXED_TEXT_ATTRS should only contain string attrs that
# require full text search.
INDEXED_TEXT_ATTRS = set()

# NON_INDEXED_TEXT_ATTRS should contain string attrs that
# are highly variable and not likely to be searched on.
# These could always be "upgraded" to indexed text/keywords
# by adding your own mapping.
NON_INDEXED_TEXT_ATTRS = {
    "AllRemoteHosts",
    "AppendFiles",
    "Args",
    "Arguments",
    "Cmd",
    "CompressFiles",
    "ContainerServiceNames",
    "DAGManNodesLog",
    "DAGManNodesMask",
    "DontEncryptInputFiles",
    "DontEncryptOutputFiles",
    "EncryptInputFiles",
    "EncryptOutputFiles",
    "Err",
    "ExitReason",
    "FetchFiles",
    "FileRemaps",
    "HoldReason",
    "In",
    "Iwd",
    "JOBGLIDEIN_ResourceName",
    "LastHoldReason",
    "LastRejMatchReason",
    "LocalFiles",
    "ManifestDir",
    "NotifyUser",
    "OnExitHoldReason",
    "OnExitRemoveReason",
    "OtherJobRemoveRequirements",
    "Out",
    "OutputDestination",
    "PeriodicHoldReason",
    "PeriodicReleaseReason",
    "PeriodicRemoveReason",
    "PostCmd",
    "PreCmd",
    "PublicInputFiles",
    "ReleaseReason",
    "RemoteIwd",
    "RemoveReason",
    "Requirements",
    "RootDir",
    "StartdIpAddr",
    "StartdPrincipal",
    "StarterIpAddr",
    "StarterPrincipal",
    "SubmitEventNotes",
    "SubmitEventUserNotes",
    "TransferCheckpoint",
    "TransferInput",
    "TransferInputRemaps",
    "TransferIntermediate",
    "TransferOutput",
    "TransferOutputRemaps",
    "TransferPlugins",
    "UserLog",
    "UserLogFile",
}

# INDEXED_KEYWORD_ATTRS should contain string attrs
# with relatively few unique values.
INDEXED_KEYWORD_ATTRS = {
    "AccountingGroup",
    "AcctGroup",
    "AcctGroupUser",
    "AssignedGPUs",
    "AutoClusterId",
    "AWSRegion",
    "BatchProject",
    "BatchQueue",
    "CloudLabelNames",
    "ConcurrencyLimits",
    "CondorPlatform",
    "CondorVersion",
    "CUDAVersion",
    "DAGNodeName",
    "DAGParentNodeNames",
    "DockerImage",
    "FileSystemDomain",
    "GLIDEIN_Entry_Name",
    "GlideinClient",
    "GlideinEntryName",
    "GlideinFactory",
    "GlideinFrontendName",
    "GlideinName",
    "GlobalJobId",
    "GridJobId",
    "GridJobStatus",
    "GridResource",
    "HoldKillSig",
    "JobBatchName",
    "JobDescription",
    "JobKeyword",
    "JobState",
    "KillSig",
    "LastRemoteHost",
    "LastRemotePool",
    "MATCH_EXP_JOB_GLIDECLIENT_Name",
    "MATCH_EXP_JOB_GLIDEIN_ClusterId",
    "MATCH_EXP_JOB_GLIDEIN_Entry_Name",
    "MATCH_EXP_JOB_GLIDEIN_Factory",
    "MATCH_EXP_JOB_GLIDEIN_Name",
    "MATCH_EXP_JOB_GLIDEIN_Schedd",
    "MATCH_EXP_JOB_GLIDEIN_SEs",
    "MATCH_EXP_JOB_GLIDEIN_Site",
    "MATCH_EXP_JOB_GLIDEIN_SiteWMS_JobId",
    "MATCH_EXP_JOB_GLIDEIN_SiteWMS_Queue",
    "MATCH_EXP_JOB_GLIDEIN_SiteWMS_Slot",
    "MATCH_EXP_JOB_GLIDEIN_SiteWMS",
    "MATCH_EXP_JOBGLIDEIN_ResourceName",
    "MyType",
    "NTDomain",
    "OAuthServicesNeeded",
    "Owner",
    "ProjectName",
    "RemoteHost",
    "RemotePool",
    "RemoveKillSig",
    "ScheddName",
    "ShouldTransferFiles",
    "SingularityImage",
    "StartdName",
    "StartdSlot",
    "Status",
    "SubmitterGlobalJobId",
    "SubmitterGroup",
    "SubmitterNegotiatingGroup",
    "TargetType",
    "Universe",
    "User",
    "WhenToTransferOutput",
    "x509UserProxyEmail",
    "x509UserProxyFirstFQAN",
    "x509UserProxyFQAN",
    "x509UserProxySubject",
    "x509UserProxyVOName",
}

# NON_INDEXED_KEYWORD_ATTRS will be stored as keywords
# but not indexed.
NON_INDEXED_KEYWORD_ATTRS = set()

FLOAT_ATTRS = {
    "CPUsUsage",
    "GPUsAverageUsage",
    "GPUsMemoryUsage",
    "JobBatchId",
    "JobDuration",
    "NetworkInputMb",
    "NetworkOutputMb",
    "Rank",
}

INT_ATTRS = {
    "AutoClusterId",
    "BatchRuntime",
    "BlockReadKbytes",
    "BlockReads",
    "BlockWriteKbytes",
    "BlockWrites",
    "BufferBlockSize",
    "BufferSize",
    "BytesRecvd",
    "BytesSent",
    "ClusterId",
    "CommittedSlotTime",
    "CommittedSuspensionTime",
    "CommittedTime",
    "CoreSize",
    "CpusProvisioned",
    "CumulativeRemoteSysCpu",
    "CumulativeRemoteUserCpu",
    "CumulativeSlotTime",
    "CumulativeSuspensionTime",
    "CumulativeTransferTime",
    "CurrentHosts",
    "DAGManJobId",
    "DataLocationsCount",
    "DelegatedProxyExpiration",
    "DiskProvisioned",
    "DiskUsage_RAW",
    "DiskUsage",
    "ErrSize",
    "ExecutableSize_RAW",
    "ExecutableSize",
    "ExitCode",
    "ExitSignal",
    "ExitStatus",
    "GpusProvisioned",
    "HoldReasonCode",
    "HoldReasonSubCode",
    "ImageSize_RAW",
    "ImageSize",
    "IOWait",
    "JobLeaseDuration",
    "JobMaxRetries",
    "JobMaxVacateTime",
    "JobPid",
    "JobPrio",
    "JobRunCount",
    "JobStatus",
    "JobSuccessExitCode",
    "JobUniverse",
    "KeepClaimIdle",
    "KillSigTimeout",
    "LastHoldReasonCode",
    "LastHoldReasonSubCode",
    "LastJobStatus",
    "LocalSysCpu",
    "LocalUserCpu",
    "MachineAttrCpus0",
    "MachineAttrSlotWeight0",
    "MachineCount",
    "MATCH_EXP_JOB_GLIDEIN_Job_Max_Time",
    "MATCH_EXP_JOB_GLIDEIN_Max_Walltime",
    "MATCH_EXP_JOB_GLIDEIN_MaxMemMBs",
    "MATCH_EXP_JOB_GLIDEIN_Memory",
    "MATCH_EXP_JOB_GLIDEIN_ProcId",
    "MATCH_EXP_JOB_GLIDEIN_ToDie",
    "MATCH_EXP_JOB_GLIDEIN_ToRetire",
    "MaxHosts",
    "MaxJobRetirementTime",
    "MaxTransferInputMB",
    "MaxTransferOutputMB",
    "MaxWallTimeMins_RAW",
    "MaxWallTimeMins",
    "MemoryProvisioned",
    "MemoryUsage",
    "MinHosts",
    "NextJobStartDelay",
    "NoopJobExitCode",
    "NoopJobExitSignal",
    "NumCkpts_RAW",
    "NumCkpts",
    "NumJobCompletions",
    "NumJobMatches",
    "NumJobReconnects",
    "NumJobStarts",
    "NumPids",
    "NumRestarts",
    "NumShadowExceptions",
    "NumShadowStarts",
    "NumSystemHolds",
    "OnExitHoldSubCode",
    "OrigMaxHosts",
    "OutSize",
    "PeriodicHoldSubCode",
    "PilotRestLifeTimeMins",
    "PostCmdExitCode",
    "PostCmdExitSignal",
    "PostJobPrio1",
    "PostJobPrio2",
    "PreCmdExitCode",
    "PreCmdExitSignal",
    "PreJobPrio1",
    "PreJobPrio2",
    "ProcId",
    "ProportionalSetSizeKb",
    "RecentBlockReadKbytes",
    "RecentBlockReads",
    "RecentBlockWriteKbytes",
    "RecentBlockWrites",
    "RecentStatsLifetimeStarter",
    "RemoteSlotID",
    "RemoteSysCpu",
    "RemoteUserCpu",
    "RemoteWallClockTime",
    "RequestCpus",
    "RequestDisk",
    "RequestGpus",
    "RequestMemory",
    "RequestVirtualMemory",
    "ResidentSetSize_RAW",
    "ResidentSetSize",
    "ScratchDirFileCount",
    "StackSize",
    "StatsLifetimeStarter",
    "SuccessCheckpointExitCode",
    "SuccessCheckpointExitSignal",
    "SuccessPostExitCode",
    "SuccessPostExitSignal",
    "SuccessPreExitCode",
    "SuccessPreExitSignal",
    "TotalSubmitProcs",
    "TotalSuspensions",
    "TransferInputSizeMB",
    "WallClockCheckpoint",
    "WindowsBuildNumber",
    "WindowsMajorVersion",
    "WindowsMinorVersion",
}

# Date attrs will be stored as epoch_seconds.
DATE_ATTRS = {
    "@timestamp",
    "CompletionDate",
    "EnteredCurrentStatus",
    "EpochWriteDate",
    "GLIDEIN_ToDie",
    "GLIDEIN_ToRetire",
    "JobCurrentFinishTransferInputDate",
    "JobCurrentFinishTransferOutputDate",
    "JobCurrentStartDate",
    "JobCurrentStartExecutingDate",
    "JobCurrentStartTransferInputDate",
    "JobCurrentStartTransferOutputDate",
    "JobDisconnectedDate",
    "JobFinishedHookDone",
    "JobLastStartDate",
    "JobLeaseExpiration",
    "JobQueueBirthdate",
    "JobStartDate",
    "LastJobLeaseRenewal",
    "LastMatchTime",
    "LastRejMatchTime",
    "LastRemoteStatusUpdate",
    "LastSuspensionTime",
    "LastVacateTime_RAW",
    "LastVacateTime",
    "MATCH_GLIDEIN_ToDie",
    "MATCH_GLIDEIN_ToRetire",
    "QDate",
    "RecordTime",
    "ShadowBday",
    "StageInFinish",
    "StageInStart",
    "StageOutFinish",
    "StageOutStart",
    "TransferInFinished",
    "TransferInQueued",
    "TransferInStarted",
    "TransferOutFinished",
    "TransferOutQueued",
    "TransferOutStarted",
}

BOOL_ATTRS = {
    "BufferFiles",
    "CurrentStatusUnknown",
    "DataflowJobSkipped",
    "DockerOverrideEntrypoint",
    "EncryptExecuteDirectory",
    "EraseOutputAndErrorOnRestart",
    "ExitBySignal",
    "GlobusResubmit",
    "IsNoopJob",
    "JobCoreDumped",
    "LeaveJobInQueue",
    "LoadProfile",
    "ManifestDesired",
    "NiceUser",
    "Nonessential",
    "OnExitHold",
    "OnExitRemove",
    "PeriodicHold",
    "PeriodicRelease",
    "PeriodicRemove",
    "PostCmdExitBySignal",
    "PreCmdExitBySignal",
    "PreserveRelativeExecutable",
    "PreserveRelativePaths",
    "RunAsOwner",
    "SendCredential",
    "SkipIfDataflow",
    "SpoolOnEvict",
    "StreamErr",
    "StreamIn",
    "StreamOut",
    "SuccessCheckpointExitBySignal",
    "SuccessPostExitBySignal",
    "SuccessPreExitBySignal",
    "TerminationPending",
    "TransferErr",
    "TransferExecutable",
    "TransferIn",
    "TransferOut",
    "TransferQueued",
    "TransferringInput",
    "TransferringOutput",
    "Use_x509UserProxy",
    "UserLogUseXML",
    "WantAdRevaluate",
    "WantCheckpoint",
    "WantCheckpointSignal",
    "WantClaiming",
    "WantCompletionVisaFromSchedD",
    "WantDelayedUpdates",
    "WantExecutionVisaFromStarter",
    "WantFTOnCheckpoint",
    "WantGracefulRemoval",
    "WantIOProxy",
    "WantMatchDiagnostics",
    "WantMatching",
    "WantParallelScheduling",
    "WantParallelSchedulingGroups",
    "WantPslotPreemption",
    "WantRemoteIO",
    "WantRemoteSyscalls",
    "WantRemoteUpdates",
    "WantResAd",
}

# Object attrs should be used for nested ClassAds
# and either dynamic templates should be used to
# refine the types for the child ClassAd attrs or
# the types should be explicitly defined.
OBJECT_ATTRS = {
    "DAG_Stats",
    "NumHoldsByReason",
    "NumVacatesByReason",
    "ToE",
    "TransferInputStats",
    "TransferOutputStats",
}

# Nested attrs should be used for lists of nested
# ClassAds. In the future, it would be nice to split
# lists of files (e.g. TransferIn/Out) and machine attrs
# into nested fields.
NESTED_ATTRS = set()

# Ignore attrs are generally assumed to potentially
# contain secrets (or paths to secrets) or are otherwise
# not considered useful for keeping around.
IGNORE_ATTRS = {
    "AzureAdminKey",
    "AzureAdminUsername",
    "AzureAuthFile",
    "ClaimId",
    "CmdHash",
    "EC2AccessKeyId",
    "EC2KeyPair",
    "EC2KeyPairFile",
    "EC2SecretAccessKey",
    "EC2SecurityGroups",
    "EC2SecurityIDs",
    "EC2UserData",
    "EC2UserDataFile",
    "Env",
    "EnvDelim",
    "Environment",
    "ExecutableSize",
    "GceAccount",
    "GceAuthFile",
    "GceJsonFile",
    "GceMetadataFile",
    "GlideinCredentialIdentifier",
    "GlideinSecurityClass",
    "JobCoreFileName",
    "JobNotification",
    "KeystoreAlias",
    "KeystoreFile",
    "KeystorePassphraseFile",
    "LastPublicClaimId",
    "PostArgs",
    "PostArguments",
    "PostEnv",
    "PostEnvironment",
    "PreArgs",
    "PreArguments",
    "PreEnv",
    "PreEnvironment",
    "PublicClaimId",
    "ScitokensFile",
    "SpooledOutputFiles",
    "orig_environment",
    "osg_environment",
}

# Dynamic templates allow for matching unmapped field names using patterns,
# and are evaluated in order. Once one field matches, the remaining
# templates are ignored.
DYNAMIC_TEMPLATES = OrderedDict()
DYNAMIC_TEMPLATES["raw_expression"] = {  # Attrs ending in "_EXPR" are generated during
    "match": r"*_EXPR",  # ad conversion for expressions that cannot be evaluated
    "mapping": {"type": "text", "norms": "false", "index": "false"},
}
DYNAMIC_TEMPLATES["date_attrs"] = {  # Attrs ending in "Date" are usually timestamps
    "match": r"*Date",
    "mapping": {"type": "date", "format": "epoch_second"},
}
DYNAMIC_TEMPLATES["provisioned_attrs"] = {  # Attrs ending in "Provisioned" are
    "match": r"*Provisioned",  # resource numbers
    "mapping": {"type": "long"},
}
DYNAMIC_TEMPLATES["resource_request_attrs"] = {  # Attrs starting with "Request" are
    "match_pattern": "regex",  # usually resource numbers
    "match": r"^Request[A-Z].*$",
    "mapping": {"type": "long"},
}
DYNAMIC_TEMPLATES["target_boolean_attrs"] = {  # Attrs starting with "Want", "Has", or
    "match_pattern": "regex",  # "Is" are usually boolean checks
    "match": r"^(Want|Has|Is)[A-Z_].*$",
    "mapping": {"type": "boolean"},
}
DYNAMIC_TEMPLATES["DEFAULT"] = {  # DEFAULT MAPPING - will be evaluated last
    "match_mapping_type": "string",  # Store unknown attrs as indexed keywords
    "mapping": {"type": "keyword", "ignore_above": MAX_KEYWORD_LEN},
}

# The metadata object should always be added to the mapping last
# because adstash controls this field.
METADATA_MAPPING = {
    "properties": {
        "condor_adstash_hostname": {"type": "keyword"},
        "condor_adstash_username": {"type": "keyword"},
        "condor_adstash_runtime": {"type": "date", "format": "epoch_second"},
        "condor_adstash_version": {"type": "keyword"},
        "condor_adstash_platform": {"type": "keyword"},
        "condor_adstash_source": {"type": "keyword"},
        "condor_history_runtime": {"type": "date", "format": "epoch_second"},
        "condor_history_host_platform": {"type": "keyword"},
        "condor_history_host_version": {"type": "keyword"},
        "condor_history_host_name": {"type": "keyword"},
    },
    "type": "object",
}


def get_default_mapping_properties():
    properties = {
        field: field_type for field, field_type in
            [(field, {"type": "text"}) for field in INDEXED_TEXT_ATTRS] +
            [(field, {"type": "text", "norms": "false", "index": "false"}) for field in NON_INDEXED_TEXT_ATTRS] +
            [(field, {"type": "keyword", "ignore_above": MAX_KEYWORD_LEN}) for field in INDEXED_KEYWORD_ATTRS] +
            [(field, {"type": "keyword", "index": "false", "ignore_above": MAX_KEYWORD_LEN}) for field in NON_INDEXED_KEYWORD_ATTRS] +
            [(field, {"type": "double"}) for field in FLOAT_ATTRS] +
            [(field, {"type": "long"}) for field in INT_ATTRS] +
            [(field, {"type": "date", "format": "epoch_second"}) for field in DATE_ATTRS] +
            [(field, {"type": "boolean"}) for field in BOOL_ATTRS] +
            [(field, {"type": "object"}) for field in OBJECT_ATTRS] +
            [(field, {"type": "nested"}) for field in NESTED_ATTRS]
    }
    return properties


def get_ignore_attrs(custom_mappings={}, custom_ignore_attrs=set()):
    # First, do not ignore any attrs that have been defined in the custom mappings
    ignore_attrs = IGNORE_ATTRS - custom_mappings.get("properties", {}).keys()
    # Then, do ignore any attrs that have been specifically configured
    ignore_attrs = ignore_attrs | custom_ignore_attrs
    return ignore_attrs


# Merging properties is more complicated than just updating
# some dictionary because sub-object properties can be
# embedded sub-dictionaries deep.
# Ideally, this function's arguments are in order of:
# 1. Default properties
# 2. Custom properties
# 3. Existing properties (since existing mappings cannot be mutated)
def merge_properties(*properties_in):
    if len(properties_in) < 2:
        raise ValueError("merge_proprties requires at least two dicts")
    if not isinstance(properties_in[0], dict):
        if len(properties_in[1:]) > 1:
            return merge_properties(*properties_in[1:])
        return properties_in[1].copy()
    properties_out = {}
    properties_out.update(properties_in[0])
    for property_in in properties_in[1:]:
        for k, v in property_in.items():
            if (k not in properties_out) or (not isinstance(v, dict)):
                properties_out[k] = v
            else:
                properties_out[k].update(merge_properties(properties_out.get(k, {}), v))
    return properties_out


# Dynamic templates are evaluated in order, and once a
# template matches a field, the rest are ignored for that field.
# The catchall "DEFAULT" template should always be last.
def merge_dynamic_templates(default_dts, custom_dts):
    dts_out = OrderedDict()

    # Updating an OrderedDict puts any new values at the bottom,
    # so the order here matters. Try to match default templates
    # first, then custom templates, and make sure the DEFAULT
    # template is last.
    dts_out.update(default_dts)
    dt_default = dts_out.pop("DEFAULT")
    dts_out.update(custom_dts)
    dts_out["DEFAULT"] = dts_out.get("DEFAULT", dt_default)

    # Return a list that can be turned into JSON
    return [{dt_name: dt} for dt_name, dt in dts_out.items()]


# This will estimate the number of fields based on the
# explicit mapping properties defined. Some of these
# mappings may be nested, so need to recurse on every
# mapping.
def count_total_fields(mapping, init=True):
    count = int(not init)
    if not (isinstance(mapping, dict) and "properties" in mapping):
        return 1
    properties = mapping["properties"]
    for _, property in properties.items():
        count += count_total_fields(property, init=False)
    return count


if __name__ == "__main__":
    test_custom_mapping_properties = {
        "TestProjectName": {"type": "keyword"},
        "DAG_Stats": {"type": "object", "dynamic": "false", "properties": {"NumJobs": {"type": "long"}}},
        "VeryNestedA": {"type": "object", "properties": {"VeryNestedB": {"type": "object", "properties": {"VeryNestedC": {"type": "boolean"}}}}},
    }
    test_custom_dynamic_templates = OrderedDict([
        ("target_test_id_attrs", {
            "match": "TestID*",
            "mapping": {"type": "long"},
        }),
        ("DEFAULT", {
            "match_mapping_type": "string",
            "mapping": {"type": "text"},
        })
    ])

    properties = merge_properties(get_default_mapping_properties(), test_custom_mapping_properties, {"metadata": METADATA_MAPPING})

    mappings = {
        "dynamic_templates": merge_dynamic_templates(DYNAMIC_TEMPLATES, test_custom_dynamic_templates),
        "properties": merge_properties(get_default_mapping_properties(), test_custom_mapping_properties, {"metadata": METADATA_MAPPING}),
        "date_detection": False,
        "numeric_detection": False,
    }

    import json
    print(json.dumps(mappings, indent=2))
    print(f"Number of explicit mappings: {count_total_fields(mappings)}")
