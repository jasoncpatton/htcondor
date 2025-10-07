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
    "AutoClusterAttrs",
    "Cmd",
    "CompressFiles",
    "ContainerServiceNames",
    "DAG_Address",
    "DAGManNodesLog",
    "DAGManNodesMask",
    "DontEncryptInputFiles",
    "DontEncryptOutputFiles",
    "EditedClusterAttrs",
    "EncryptInputFiles",
    "EncryptOutputFiles",
    "Err",
    "ExitReason",
    "FetchFiles",
    "FileRemaps",
    "HoldReason",
    "In",
    "Iwd",
    "JobAdInformationAttrs",
    "JobMachineAttrs",
    "JobMaterializeDigestFile",
    "JobMaterializeItemsFile",
    "JobStarterLog",
    "LastHoldReason",
    "LastRejMatchReason",
    "LastReleaseReason",
    "LastShadowException",
    "LocalFiles",
    "ManifestDir",
    "NotifyUser",
    "OnExitHoldReason",
    "OnExitRemoveReason",
    "OriginalOut",
    "OSHomeDir",
    "OtherJobRemoveRequirements",
    "Out",
    "OutputDestination",
    "PeriodicHoldReason",
    "PeriodicReleaseReason",
    "PeriodicRemoveReason",
    "PeriodicVacateReason",
    "PostCmd",
    "PreCmd",
    "PublicInputFiles",
    "ReleaseReason",
    "RemoteIwd",
    "RemoveReason",
    "RequeueReason",
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
    "UserLogExecuteEventAttrs",
    "UserLogFile",
    "VacateReason",
    "VMPARAM_vm_Disk",
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
    "ContainerImage",
    "ContainerImageSource",
    "CronDayOfMonth",
    "CronDayOfWeek",
    "CronHour",
    "CronMinute",
    "CronMonth",
    "CUDAVersion",
    "DAGNodeName",
    "DAGParentNodeNames",
    "DockerImage",
    "DockerNetworkType",
    "DockerPullPolicy",
    "EpochAdType",
    "FileSystemDomain",
    "GlobalJobId",
    "GridJobId",
    "GridJobStatus",
    "GridResource",
    "HoldKillSig",
    "JobBatchName",
    "JobDescription",
    "JobKeyword",
    "JobStarterDebug",
    "JobState",
    "JobSubmitFile",
    "JobVMType",
    "KillSig",
    "LastFileTransferErrorProtocol",
    "LastRejMatchNegotiator",
    "LastRemoteHost",
    "LastRemotePool",
    "Managed",
    "MyType",
    "NTDomain",
    "OAuthServicesNeeded",
    "OsUser",
    "Owner",
    "PrimaryUnixGroup",
    "ProjectName",
    "ProvisionedResources",
    "RemoteHost",
    "RemotePool",
    "RemoveKillSig",
    "RequestedAcctGroup",
    "ScheddName",
    "ShouldTransferFiles",
    "SingularityImage",
    "StartdName",
    "StartdSlot",
    "Status",
    "SubmitterGlobalJobId",
    "SubmitterGroup",
    "SubmitterNegotiatingGroup",
    "TargetAnnexName",
    "TargetType",
    "Universe",
    "User",
    "WantTransferPluginMethods",
    "WhenToTransferOutput",
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
    "JobVMCpuUtilization",
    "NetworkInputMb",
    "NetworkOutputMb",
    "Rank",
}

INT_ATTRS = {
    "ActivationDuration",
    "ActivationExecutionDuration",
    "ActivationSetupDuration",
    "ActivationTeardownDuration",
    "AllowedExecuteDuration",
    "AllowedJobDuration",
    "AutoClusterId",
    "BatchRuntime",
    "BlockReadBytes",
    "BlockReadKbytes",
    "BlockReads",
    "BlockWriteBytes",
    "BlockWriteKbytes",
    "BlockWrites",
    "BufferBlockSize",
    "BufferSize",
    "BytesRecvd",
    "BytesSent",
    "CheckpointNumber",
    "ClusterId",
    "CommittedSlotTime",
    "CommittedSuspensionTime",
    "CommittedTime",
    "CoreSize",
    "CPUInstructions",
    "CpusProvisioned",
    "CumulativeRemoteSysCpu",
    "CumulativeRemoteUserCpu",
    "CumulativeSlotTime",
    "CumulativeSuspensionTime",
    "CumulativeTransferTime",
    "CurrentHosts",
    "DAG_JobsCompleted",
    "DAG_JobsHeld",
    "DAG_JobsIdle",
    "DAG_JobsRunning",
    "DAG_JobsSubmitted",
    "DAG_NodesDone",
    "DAG_NodesFailed",
    "DAG_NodesFutile",
    "DAG_NodesHoldrun",
    "DAG_NodesPostrun",
    "DAG_NodesPrerun",
    "DAG_NodesQueued",
    "DAG_NodesReady",
    "DAG_NodesTotal",
    "DAG_NodesUnready",
    "DAG_Status",
    "DAGMan_MaxHoldScripts",
    "DAGMan_MaxIdle",
    "DAGMan_MaxJobs",
    "DAGMan_MaxPostScripts",
    "DAGMan_MaxPreScripts",
    "DAGManJobId",
    "DAGManNodeRetry",
    "DataLocationsCount",
    "DeferralPrepTime",
    "DeferralWindow",
    "DiskProvisioned",
    "DiskUsage_RAW",
    "DiskUsage",
    "ErrSize",
    "ExecutableSize_RAW",
    "ExecutableSize",
    "ExitCode",
    "ExitSignal",
    "ExitStatus",
    "GPUsMaxCapability",
    "GPUsMinCapability",
    "GPUsMinMemory",
    "GPUsMinRuntime",
    "GpusProvisioned",
    "HoldReasonCode",
    "HoldReasonSubCode",
    "ImageSize_RAW",
    "ImageSize",
    "InitialWaitDuration",
    "IOWait",
    "JobCurrentReconnectAttempt",
    "JobLeaseDuration",
    "JobMachineAttrsHistoryLength",
    "JobMaterializeLimit",
    "JobMaterializeMaxIdle",
    "JobMaterializeNextProcId",
    "JobMaterializeNextRow",
    "JobMaterializePaused",
    "JobMaxRetries",
    "JobMaxVacateTime",
    "JobPid",
    "JobPrio",
    "JobRunCount",
    "JobStatus",
    "JobStatusOnRelease",
    "JobSubmitMethod",
    "JobSuccessExitCode",
    "JobUniverse",
    "JobVM_VCPUS",
    "JobVMMemory",
    "KeepClaimIdle",
    "KillSigTimeout",
    "LastHoldReasonCode",
    "LastHoldReasonSubCode",
    "LastJobStatus",
    "LastRemoteWallClockTime",
    "LocalSysCpu",
    "LocalUserCpu",
    "MachineAttrCpus0",
    "MachineAttrSlotWeight0",
    "MachineCount",
    "MaxHosts",
    "MaxJobRetirementTime",
    "MaxRequestMemory",
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
    "NumHolds",
    "NumInputTransferStarts",
    "NumJobCompletions",
    "NumJobCoolDowns",
    "NumJobMatches",
    "NumJobReconnects",
    "NumJobStarts",
    "NumOutputTransferStarts",
    "NumPids",
    "NumRestarts",
    "NumShadowExceptions",
    "NumShadowStarts",
    "NumSystemHolds",
    "NumVacates",
    "OnExitHoldSubCode",
    "OrigMaxHosts",
    "OutSize",
    "PelicanRetryDelay",
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
    "ProportionalSetSizeKb_RAW",
    "ProportionalSetSizeKb",
    "RecentBlockReadBytes",
    "RecentBlockReadKbytes",
    "RecentBlockReads",
    "RecentBlockWriteBytes",
    "RecentBlockWriteKbytes",
    "RecentBlockWrites",
    "RecentStatsLifetime",
    "RecentStatsLifetimeStarter",
    "RecentWindowMax",
    "RecentWindowMaxStarter",
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
    "RetryRequestMemory",
    "ScratchDirFileCount",
    "StackSize",
    "StatsLifetime",
    "StatsLifetimeStarter",
    "SuccessCheckpointExitCode",
    "SuccessCheckpointExitSignal",
    "SuccessPostExitCode",
    "SuccessPostExitSignal",
    "SuccessPreExitCode",
    "SuccessPreExitSignal",
    "TotalJobReconnectAttempts",
    "TotalSubmitProcs",
    "TotalSuspensions",
    "TransferInputSizeMB",
    "VacateReasonCode",
    "VacateReasonSubCode",
    "WallClockCheckpoint",
    "WindowsBuildNumber",
    "WindowsMajorVersion",
    "WindowsMinorVersion",
}

# Date attrs will be stored as epoch_seconds.
DATE_ATTRS = {
    "@timestamp",
    "CompletionDate",
    "DAG_AdUpdateTime",
    "DeferralTime",
    "EnteredCurrentStatus",
    "EpochWriteDate",
    "FirstJobMatchDate",
    "JobCoolDownExpiration",
    "JobCurrentFinishTransferInputDate",
    "JobCurrentFinishTransferOutputDate",
    "JobCurrentStartDate",
    "JobCurrentStartExecutingDate",
    "JobCurrentStartTransferInputDate",
    "JobCurrentStartTransferOutputDate",
    "JobDisconnectedDate",
    "JobFinishedHookDone",
    "JobLastCheckpointTime",
    "JobLastStartDate",
    "JobLeaseExpiration",
    "JobMaterializeDate",
    "JobQueueBirthdate",
    "JobStartDate",
    "LastJobLeaseRenewal",
    "LastMatchTime",
    "LastRejMatchTime",
    "LastRemoteStatusUpdate",
    "LastSuspensionTime",
    "LastVacateTime_RAW",
    "LastVacateTime",
    "QDate",
    "RecentStatsTickTime",
    "RecentStatsTickTimeStarter",
    "RecordTime",
    "ShadowBday",
    "StageInFinish",
    "StageInStart",
    "StageOutFinish",
    "StageOutStart",
    "StatsLastUpdateTime",
    "StatsLastUpdateTimeStarter",
    "StderrMtime",
    "StdoutMtime",
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
    "DAG_InRecovery",
    "DAGLifetimeJob",
    "DataflowJobSkipped",
    "DockerOverrideEntrypoint",
    "EncryptExecuteDirectory",
    "EraseOutputAndErrorOnRestart",
    "ExecuteDirWasEncrypted",
    "ExitBySignal",
    "GlobusResubmit",
    "IsDaemonCore",
    "IsNoopJob",
    "JobCoreDumped",
    "JobRequiresSandbox",
    "JobVMCheckpoint",
    "JobVMNetworking",
    "JobVMVNCConsole",
    "LeaveJobInQueue",
    "LoadProfile",
    "ManifestDesired",
    "NiceUser",
    "Nonessential",
    "OnExitHold",
    "OnExitRemove",
    "PelicanRetryEnabled",
    "PeriodicHold",
    "PeriodicRelease",
    "PeriodicRemove",
    "PeriodicVacate",
    "PostCmdExitBySignal",
    "PreCmdExitBySignal",
    "PreserveRelativeExecutable",
    "PreserveRelativePath",
    "PreserveRelativePaths",
    "RequireGPUs",
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
    "TransferContainer",
    "TransferErr",
    "TransferExecutable",
    "TransferIn",
    "TransferOut",
    "TransferQueued",
    "TransferringInput",
    "TransferringOutput",
    "Use_x509UserProxy",
    "UserLogUseXML",
    "VMPARAM_No_Output_VM",
    "WantAdRevaluate",
    "WantCheckpoint",
    "WantCheckpointSignal",
    "WantClaiming",
    "WantCompletionVisaFromSchedD",
    "WantContainer",
    "WantDelayedUpdates",
    "WantDocker",
    "WantDockerImage",
    "WantExecutionVisaFromStarter",
    "WantFTOnCheckpoint",
    "WantGracefulRemoval",
    "WantIOProxy",
    "WantJobNetworking",
    "WantMatchDiagnostics",
    "WantMatching",
    "WantParallelScheduling",
    "WantParallelSchedulingGroups",
    "WantPslotPreemption",
    "WantRemoteIO",
    "WantRemoteSyscalls",
    "WantRemoteUpdates",
    "WantResAd",
    "WantSandboxImage",
    "WantSIF",
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
    "TransferInputFileCounts",
    "TransferInputStats",
    "TransferOutputFileCounts",
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
    "AuthTokenGroups",
    "AuthTokenId",
    "AuthTokenIssuer",
    "AuthTokenScopes",
    "AuthTokenSubject",
    "AzureAdminKey",
    "AzureAdminUsername",
    "AzureAuthFile",
    "ClaimId",
    "CmdHash",
    "DelegatedProxyExpiration",
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
    "MyAddress",
    "orig_environment",
    "osg_environment",
    "PostArgs",
    "PostArguments",
    "PostEnv",
    "PostEnvironment",
    "PreArgs",
    "PreArguments",
    "PreEnv",
    "PreEnvironment",
    "PublicClaimId",
    "RunInstanceID",
    "ScitokensFile",
    "ShadowIpAddr",
    "ShadowVersion",
    "SpooledOutputFiles",
    "TransferSocket",
    "UidDomain",
    "x509UserProxy",
    "x509UserProxyEmail",
    "x509UserProxyExpiration",
    "x509UserProxyFirstFQAN",
    "x509UserProxyFQAN",
    "x509UserProxySubject",
    "x509UserProxyVOName",
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
DYNAMIC_TEMPLATES["num_attrs"] = {  # Attrs starting with Num are usually numbers
    "match_pattern": "regex",
    "match": r"Num[A-Z].*",
    "mapping": {"type": "long"},
}
DYNAMIC_TEMPLATES["stats_attrs"] = {  # Attrs ending with Stats are usually
    "match_pattern": "regex",  # ClassAds containing floating point numbers
    "match": r".*Stats\..*",
    "mapping": {"type": "double"},
}
DYNAMIC_TEMPLATES["counts_attrs"] = {  # Attrs ending with Counts are usually
    "match_pattern": "regex",  # ClassAds containing numbers
    "match": r".*Counts\..*",
    "mapping": {"type": "long"},
}
DYNAMIC_TEMPLATES["resource_request_attrs"] = {  # Attrs starting with "Request" are
    "match_pattern": "regex",  # usually resource numbers
    "match": r"^Request[A-Z].*$",
    "mapping": {"type": "long"},
}
DYNAMIC_TEMPLATES["target_bool_attrs"] = {  # Attrs starting with "Want", "Has", or
    "match_pattern": "regex",  # "Is" are usually boolean checks
    "match": r"^(Want|Has|Is)[A-Z_].*$",
    "mapping": {"type": "boolean"},
}
DYNAMIC_TEMPLATES["DEFAULT"] = {  # DEFAULT MAPPING - will be evaluated last
    "match_mapping_type": "string",  # Store unknown attrs as indexed keywords
    "mapping": {"type": "keyword", "ignore_above": MAX_KEYWORD_LEN},  # https://www.elastic.co/guide/en/elasticsearch/reference/7.17/tune-for-disk-usage.html#default-dynamic-string-mapping
}

# The metadata object should always be added to the mapping last
# because adstash controls this field.
METADATA_MAPPING = {
    "metadata": {
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
    },
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
            [(field, {"type": "object", "dynamic": True}) for field in OBJECT_ATTRS] +
            [(field, {"type": "nested", "dynamic": True}) for field in NESTED_ATTRS]
    }
    return properties


def get_ignore_attrs(custom_mappings={}, custom_ignore_attrs=set()):
    # First, duplicate lowercase version of defaults
    ignore_attrs = IGNORE_ATTRS | {attr.lower() for attr in IGNORE_ATTRS}
    # Then, do not ignore any attrs that have been defined in the custom mappings
    ignore_attrs = ignore_attrs - custom_mappings.get("properties", {}).keys()
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

    properties = merge_properties(get_default_mapping_properties(), test_custom_mapping_properties, METADATA_MAPPING)

    mappings = {
        "dynamic_templates": merge_dynamic_templates(DYNAMIC_TEMPLATES, test_custom_dynamic_templates),
        "properties": properties,
        "date_detection": False,
        "numeric_detection": False,
    }

    import json
    print(json.dumps(mappings, indent=2))
    print(f"Number of explicit mappings: {count_total_fields(mappings)}")
