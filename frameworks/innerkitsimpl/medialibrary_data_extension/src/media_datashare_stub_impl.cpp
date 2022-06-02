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

#include "media_datashare_stub_impl.h"

#include "datashare_log.h"

namespace OHOS {
namespace DataShare {
std::shared_ptr<MediaDataShareExtAbility> MediaDataShareStubImpl::GetOwner()
{
    return extension_;
}

std::vector<std::string> MediaDataShareStubImpl::GetFileTypes(const Uri &uri, const std::string &mimeTypeFilter)
{
    LOG_INFO("begin.");
    std::vector<std::string> ret;
    auto client = sptr<MediaDataShareStubImpl>(this);
    auto extension = client->GetOwner();
    if (extension == nullptr) {
        LOG_ERROR("%{public}s end failed.", __func__);
        return ret;
    }
    ret = extension->GetFileTypes(uri, mimeTypeFilter);
    LOG_INFO("end successfully.");
    return ret;
}

int MediaDataShareStubImpl::OpenFile(const Uri &uri, const std::string &mode)
{
    LOG_INFO("begin.");
    int ret = -1;
    auto client = sptr<MediaDataShareStubImpl>(this);
    auto extension = client->GetOwner();
    if (extension == nullptr) {
        LOG_ERROR("%{public}s end failed.", __func__);
        return ret;
    }
    ret = extension->OpenFile(uri, mode);
    LOG_INFO("end successfully.");
    return ret;
}

int MediaDataShareStubImpl::OpenRawFile(const Uri &uri, const std::string &mode)
{
    LOG_INFO("begin.");
    int ret = -1;
    auto client = sptr<MediaDataShareStubImpl>(this);
    auto extension = client->GetOwner();
    if (extension == nullptr) {
            LOG_ERROR("%{public}s end failed.", __func__);
            return ret;
    }
    ret = extension->OpenRawFile(uri, mode);
    LOG_INFO("end successfully.");
    return ret;
}

int MediaDataShareStubImpl::Insert(const Uri &uri, const DataShareValuesBucket &value)
{
    LOG_INFO("begin.");
    int ret = 0;
    auto client = sptr<MediaDataShareStubImpl>(this);
    auto extension = client->GetOwner();
    if (extension == nullptr) {
        LOG_ERROR("%{public}s end failed.", __func__);
        return ret;
    }
    ret = extension->Insert(uri, value);
    LOG_INFO("end successfully.");
    return ret;
}

int MediaDataShareStubImpl::Update(const Uri &uri, const DataSharePredicates &predicates,
    const DataShareValuesBucket &value)
{
    LOG_INFO("begin.");
    int ret = 0;
    auto client = sptr<MediaDataShareStubImpl>(this);
    auto extension = client->GetOwner();
    if (extension == nullptr) {
        LOG_ERROR("%{public}s end failed.", __func__);
        return ret;
    }
    ret = extension->Update(uri, predicates, value);
    LOG_INFO("end successfully.");
    return ret;
}

int MediaDataShareStubImpl::Delete(const Uri &uri, const DataSharePredicates &predicates)
{
    LOG_INFO("begin.");
    int ret = 0;
    auto client = sptr<MediaDataShareStubImpl>(this);
    auto extension = client->GetOwner();
    if (extension == nullptr) {
        LOG_ERROR("%{public}s end failed.", __func__);
        return ret;
    }
    ret = extension->Delete(uri, predicates);
    LOG_INFO("end successfully.");
    return ret;
}

std::shared_ptr<DataShareResultSet> MediaDataShareStubImpl::Query(const Uri &uri,
    const DataSharePredicates &predicates, std::vector<std::string> &columns)
{
    LOG_INFO("begin.");
    std::shared_ptr<DataShareResultSet> resultSet = nullptr;
    auto client = sptr<MediaDataShareStubImpl>(this);
    auto extension = client->GetOwner();
    if (extension == nullptr) {
        LOG_ERROR("%{public}s end failed.", __func__);
        return nullptr;
    }
    resultSet = extension->Query(uri, predicates, columns);
    LOG_INFO("end successfully.");
    return resultSet;
}

std::string MediaDataShareStubImpl::GetType(const Uri &uri)
{
    LOG_INFO("begin.");
    std::string ret = "";
    auto client = sptr<MediaDataShareStubImpl>(this);
    auto extension = client->GetOwner();
    if (extension == nullptr) {
        LOG_ERROR("%{public}s end failed.", __func__);
        return ret;
    }
    ret = extension->GetType(uri);
    LOG_INFO("end successfully.");
    return ret;
}

int MediaDataShareStubImpl::BatchInsert(const Uri &uri, const std::vector<DataShareValuesBucket> &values)
{
    LOG_INFO("begin.");
    int ret = 0;
    auto client = sptr<MediaDataShareStubImpl>(this);
    auto extension = client->GetOwner();
    if (extension == nullptr) {
        LOG_ERROR("%{public}s end failed.", __func__);
        return ret;
    }
    ret = extension->BatchInsert(uri, values);
    LOG_INFO("end successfully.");
    return ret;
}

bool MediaDataShareStubImpl::RegisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver)
{
    LOG_INFO("begin.");
    bool ret = false;
    auto client = sptr<MediaDataShareStubImpl>(this);
    auto extension = client->GetOwner();
    if (extension == nullptr) {
        LOG_ERROR("%{public}s end failed.", __func__);
        return ret;
    }
    ret = extension->RegisterObserver(uri, dataObserver);
    LOG_INFO("end successfully.");
    return ret;
}

bool MediaDataShareStubImpl::UnregisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver)
{
    LOG_INFO("begin.");
    bool ret = false;
    auto client = sptr<MediaDataShareStubImpl>(this);
    auto extension = client->GetOwner();
    if (extension == nullptr) {
        LOG_ERROR("%{public}s end failed.", __func__);
        return ret;
    }
    ret = extension->UnregisterObserver(uri, dataObserver);
    LOG_INFO("end successfully.");
    return ret;
}

bool MediaDataShareStubImpl::NotifyChange(const Uri &uri)
{
    LOG_INFO("begin.");
    bool ret = false;
    auto client = sptr<MediaDataShareStubImpl>(this);
    auto extension = client->GetOwner();
    if (extension == nullptr) {
        LOG_ERROR("%{public}s end failed.", __func__);
        return ret;
    }
    ret = extension->NotifyChange(uri);
    LOG_INFO("end successfully.");
    return ret;
}

Uri MediaDataShareStubImpl::NormalizeUri(const Uri &uri)
{
    LOG_INFO("begin.");
    Uri urivalue("");
    auto client = sptr<MediaDataShareStubImpl>(this);
    auto extension = client->GetOwner();
    if (extension == nullptr) {
        LOG_ERROR("%{public}s end failed.", __func__);
        return urivalue;
    }
    urivalue = extension->NormalizeUri(uri);
    LOG_INFO("end successfully.");
    return urivalue;
}

Uri MediaDataShareStubImpl::DenormalizeUri(const Uri &uri)
{
    LOG_INFO("begin.");
    Uri urivalue("");
    auto client = sptr<MediaDataShareStubImpl>(this);
    auto extension = client->GetOwner();
    if (extension == nullptr) {
        LOG_ERROR("%{public}s end failed.", __func__);
        return urivalue;
    }
    urivalue = extension->DenormalizeUri(uri);
    LOG_INFO("end successfully.");
    return urivalue;
}

std::vector<std::shared_ptr<DataShareResult>> MediaDataShareStubImpl::ExecuteBatch(
    const std::vector<std::shared_ptr<DataShareOperation>> &operations)
{
    LOG_INFO("begin.");
    std::vector<std::shared_ptr<DataShareResult>> results;
    auto client = sptr<MediaDataShareStubImpl>(this);
    auto extension = client->GetOwner();
    if (extension == nullptr) {
        LOG_ERROR("%{public}s end failed.", __func__);
        return results;
    }
    results = extension->ExecuteBatch(operations);
    LOG_INFO("end successfully.");
    return results;
}
} // namespace DataShare
} // namespace OHOS
