/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mediadata_stub_impl.h"

#include "hilog_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
std::vector<std::string> MediaDataStubImpl::GetFileTypes(const Uri &uri, const std::string &mimeTypeFilter)
{
    HILOG_INFO("%{public}s begin.", __func__);
    std::vector<std::string> ret;
    HILOG_INFO("%{public}s end successfully.", __func__);
    return ret;
}

int MediaDataStubImpl::OpenFile(const Uri &uri, const std::string &mode)
{
    HILOG_INFO("%{public}s begin.", __func__);
    int ret = -1;
    HILOG_INFO("%{public}s end successfully.", __func__);
    return ret;
}

int MediaDataStubImpl::OpenRawFile(const Uri &uri, const std::string &mode)
{
    HILOG_INFO("%{public}s begin.", __func__);
    int ret = -1;
    HILOG_INFO("%{public}s end successfully.", __func__);
    return ret;
}

int MediaDataStubImpl::Insert(const Uri &uri, const NativeRdb::ValuesBucket &value)
{
    HILOG_INFO("%{public}s begin.", __func__);
    int ret = 0;
    HILOG_INFO("%{public}s end successfully.", __func__);
    return ret;
}

int MediaDataStubImpl::Update(const Uri &uri, const NativeRdb::ValuesBucket &value,
    const NativeRdb::DataAbilityPredicates &predicates)
{
    HILOG_INFO("%{public}s begin.", __func__);
    int ret = 0;
    HILOG_INFO("%{public}s end successfully.", __func__);
    return ret;
}

int MediaDataStubImpl::Delete(const Uri &uri, const NativeRdb::DataAbilityPredicates &predicates)
{
    HILOG_INFO("%{public}s begin.", __func__);
    int ret = 0;
    HILOG_INFO("%{public}s end successfully.", __func__);
    return ret;
}

std::shared_ptr<NativeRdb::AbsSharedResultSet> MediaDataStubImpl::Query(const Uri &uri,
    std::vector<std::string> &columns, const NativeRdb::DataAbilityPredicates &predicates)
{
    HILOG_INFO("%{public}s begin.", __func__);
    std::shared_ptr<NativeRdb::AbsSharedResultSet> ret = nullptr;
    HILOG_INFO("%{public}s end successfully.", __func__);
    return ret;
}

std::string MediaDataStubImpl::GetType(const Uri &uri)
{
    HILOG_INFO("%{public}s begin.", __func__);
    std::string ret = "";
    HILOG_INFO("%{public}s end successfully.", __func__);
    return ret;
}

int MediaDataStubImpl::BatchInsert(const Uri &uri, const std::vector<NativeRdb::ValuesBucket> &values)
{
    HILOG_INFO("%{public}s begin.", __func__);
    int ret = 0;
    HILOG_INFO("%{public}s end successfully.", __func__);
    return ret;
}

bool MediaDataStubImpl::RegisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver)
{
    HILOG_INFO("%{public}s begin.", __func__);
    bool ret = false;
    HILOG_INFO("%{public}s end successfully.", __func__);
    return ret;
}

bool MediaDataStubImpl::UnregisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver)
{
    HILOG_INFO("%{public}s begin.", __func__);
    bool ret = false;
    HILOG_INFO("%{public}s end successfully.", __func__);
    return ret;
}

bool MediaDataStubImpl::NotifyChange(const Uri &uri)
{
    HILOG_INFO("%{public}s begin.", __func__);
    bool ret = false;
    HILOG_INFO("%{public}s end successfully.", __func__);
    return ret;
}

Uri MediaDataStubImpl::NormalizeUri(const Uri &uri)
{
    HILOG_INFO("%{public}s begin.", __func__);
    Uri urivalue("");
    HILOG_INFO("%{public}s end successfully.", __func__);
    return urivalue;
}

Uri MediaDataStubImpl::DenormalizeUri(const Uri &uri)
{
    HILOG_INFO("%{public}s begin.", __func__);
    Uri urivalue("");
    HILOG_INFO("%{public}s end successfully.", __func__);
    return urivalue;
}

std::vector<std::shared_ptr<AppExecFwk::DataAbilityResult>> MediaDataStubImpl::ExecuteBatch(
    const std::vector<std::shared_ptr<AppExecFwk::DataAbilityOperation>> &operations)
{
    HILOG_INFO("%{public}s begin.", __func__);
    std::vector<std::shared_ptr<DataAbilityResult>> results;
    HILOG_INFO("%{public}s end successfully.", __func__);
    return results;
}
} // namespace AppExecFwk
} // namespace OHOS
