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
#define MLOG_TAG "Extension"

#include "media_datashare_stub_impl.h"

#include "media_log.h"

namespace OHOS {
namespace DataShare {
std::shared_ptr<MediaDataShareExtAbility> MediaDataShareStubImpl::GetOwner()
{
    return extension_;
}

std::vector<std::string> MediaDataShareStubImpl::GetFileTypes(const Uri &uri, const std::string &mimeTypeFilter)
{
    MEDIA_INFO_LOG("begin.");
    std::vector<std::string> ret;
    auto client = sptr<MediaDataShareStubImpl>(this);
    auto extension = client->GetOwner();
    if (extension == nullptr) {
        MEDIA_ERR_LOG("%{public}s end failed.", __func__);
        return ret;
    }
    ret = extension->GetFileTypes(uri, mimeTypeFilter);
    MEDIA_INFO_LOG("end successfully.");
    return ret;
}

int MediaDataShareStubImpl::OpenFile(const Uri &uri, const std::string &mode)
{
    MEDIA_INFO_LOG("begin.");
    int ret = -1;
    auto client = sptr<MediaDataShareStubImpl>(this);
    auto extension = client->GetOwner();
    if (extension == nullptr) {
        MEDIA_ERR_LOG("%{public}s end failed.", __func__);
        return ret;
    }
    ret = extension->OpenFile(uri, mode);
    MEDIA_INFO_LOG("end successfully. ret: %{public}d", ret);
    return ret;
}

int MediaDataShareStubImpl::OpenRawFile(const Uri &uri, const std::string &mode)
{
    MEDIA_INFO_LOG("begin.");
    int ret = -1;
    auto client = sptr<MediaDataShareStubImpl>(this);
    auto extension = client->GetOwner();
    if (extension == nullptr) {
            MEDIA_ERR_LOG("%{public}s end failed.", __func__);
            return ret;
    }
    ret = extension->OpenRawFile(uri, mode);
    MEDIA_INFO_LOG("end successfully. ret: %{public}d", ret);
    return ret;
}

int MediaDataShareStubImpl::Insert(const Uri &uri, const DataShareValuesBucket &value)
{
    MEDIA_INFO_LOG("begin.");
    int ret = 0;
    auto client = sptr<MediaDataShareStubImpl>(this);
    auto extension = client->GetOwner();
    if (extension == nullptr) {
        MEDIA_ERR_LOG("%{public}s end failed.", __func__);
        return ret;
    }
    ret = extension->Insert(uri, value);
    MEDIA_INFO_LOG("end successfully. ret: %{public}d", ret);
    return ret;
}

int MediaDataShareStubImpl::Update(const Uri &uri, const DataSharePredicates &predicates,
    const DataShareValuesBucket &value)
{
    MEDIA_INFO_LOG("begin.");
    int ret = 0;
    auto client = sptr<MediaDataShareStubImpl>(this);
    auto extension = client->GetOwner();
    if (extension == nullptr) {
        MEDIA_ERR_LOG("%{public}s end failed.", __func__);
        return ret;
    }
    ret = extension->Update(uri, predicates, value);
    MEDIA_INFO_LOG("end successfully. ret: %{public}d", ret);
    return ret;
}

int MediaDataShareStubImpl::Delete(const Uri &uri, const DataSharePredicates &predicates)
{
    MEDIA_INFO_LOG("begin.");
    int ret = 0;
    auto client = sptr<MediaDataShareStubImpl>(this);
    auto extension = client->GetOwner();
    if (extension == nullptr) {
        MEDIA_ERR_LOG("%{public}s end failed.", __func__);
        return ret;
    }
    ret = extension->Delete(uri, predicates);
    MEDIA_INFO_LOG("end successfully. ret: %{public}d", ret);
    return ret;
}

std::shared_ptr<DataShareResultSet> MediaDataShareStubImpl::Query(const Uri &uri,
    const DataSharePredicates &predicates, std::vector<std::string> &columns)
{
    MEDIA_INFO_LOG("begin.");
    std::shared_ptr<DataShareResultSet> resultSet = nullptr;
    auto client = sptr<MediaDataShareStubImpl>(this);
    auto extension = client->GetOwner();
    if (extension == nullptr) {
        MEDIA_ERR_LOG("%{public}s end failed.", __func__);
        return nullptr;
    }
    resultSet = extension->Query(uri, predicates, columns);
    MEDIA_INFO_LOG("end successfully.");
    return resultSet;
}

std::string MediaDataShareStubImpl::GetType(const Uri &uri)
{
    MEDIA_INFO_LOG("begin.");
    std::string ret = "";
    auto client = sptr<MediaDataShareStubImpl>(this);
    auto extension = client->GetOwner();
    if (extension == nullptr) {
        MEDIA_ERR_LOG("%{public}s end failed.", __func__);
        return ret;
    }
    ret = extension->GetType(uri);
    MEDIA_INFO_LOG("end successfully.");
    return ret;
}

int MediaDataShareStubImpl::BatchInsert(const Uri &uri, const std::vector<DataShareValuesBucket> &values)
{
    MEDIA_INFO_LOG("begin.");
    int ret = 0;
    auto client = sptr<MediaDataShareStubImpl>(this);
    auto extension = client->GetOwner();
    if (extension == nullptr) {
        MEDIA_ERR_LOG("%{public}s end failed.", __func__);
        return ret;
    }
    ret = extension->BatchInsert(uri, values);
    MEDIA_INFO_LOG("end successfully.");
    return ret;
}

bool MediaDataShareStubImpl::RegisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver)
{
    MEDIA_INFO_LOG("begin.");
    bool ret = false;
    auto client = sptr<MediaDataShareStubImpl>(this);
    auto extension = client->GetOwner();
    if (extension == nullptr) {
        MEDIA_ERR_LOG("%{public}s end failed.", __func__);
        return ret;
    }
    ret = extension->RegisterObserver(uri, dataObserver);
    MEDIA_INFO_LOG("end successfully. ret: %{public}d", ret);
    return ret;
}

bool MediaDataShareStubImpl::UnregisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver)
{
    MEDIA_INFO_LOG("begin.");
    bool ret = false;
    auto client = sptr<MediaDataShareStubImpl>(this);
    auto extension = client->GetOwner();
    if (extension == nullptr) {
        MEDIA_ERR_LOG("%{public}s end failed.", __func__);
        return ret;
    }
    ret = extension->UnregisterObserver(uri, dataObserver);
    MEDIA_INFO_LOG("end successfully. ret: %{public}d", ret);
    return ret;
}

bool MediaDataShareStubImpl::NotifyChange(const Uri &uri)
{
    MEDIA_INFO_LOG("begin.");
    bool ret = false;
    auto client = sptr<MediaDataShareStubImpl>(this);
    auto extension = client->GetOwner();
    if (extension == nullptr) {
        MEDIA_ERR_LOG("%{public}s end failed.", __func__);
        return ret;
    }
    ret = extension->NotifyChange(uri);
    MEDIA_INFO_LOG("end successfully. ret: %{public}d", ret);
    return ret;
}

Uri MediaDataShareStubImpl::NormalizeUri(const Uri &uri)
{
    MEDIA_INFO_LOG("begin.");
    Uri urivalue("");
    auto client = sptr<MediaDataShareStubImpl>(this);
    auto extension = client->GetOwner();
    if (extension == nullptr) {
        MEDIA_ERR_LOG("%{public}s end failed.", __func__);
        return urivalue;
    }
    urivalue = extension->NormalizeUri(uri);
    MEDIA_INFO_LOG("end successfully.");
    return urivalue;
}

Uri MediaDataShareStubImpl::DenormalizeUri(const Uri &uri)
{
    MEDIA_INFO_LOG("begin.");
    Uri urivalue("");
    auto client = sptr<MediaDataShareStubImpl>(this);
    auto extension = client->GetOwner();
    if (extension == nullptr) {
        MEDIA_ERR_LOG("%{public}s end failed.", __func__);
        return urivalue;
    }
    urivalue = extension->DenormalizeUri(uri);
    MEDIA_INFO_LOG("end successfully.");
    return urivalue;
}
} // namespace DataShare
} // namespace OHOS
