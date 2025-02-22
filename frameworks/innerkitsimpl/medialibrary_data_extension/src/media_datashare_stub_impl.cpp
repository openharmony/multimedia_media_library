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
    MEDIA_DEBUG_LOG("begin.");
    std::vector<std::string> ret;
    auto client = sptr<MediaDataShareStubImpl>(this);
    auto extension = client->GetOwner();
    CHECK_AND_RETURN_RET_LOG(extension != nullptr, ret, "%{public}s end failed.", __func__);
    ret = extension->GetFileTypes(uri, mimeTypeFilter);
    MEDIA_DEBUG_LOG("end successfully.");
    return ret;
}

int MediaDataShareStubImpl::OpenFile(const Uri &uri, const std::string &mode)
{
    int ret = -1;
    auto client = sptr<MediaDataShareStubImpl>(this);
    auto extension = client->GetOwner();
    CHECK_AND_RETURN_RET_LOG(extension != nullptr, ret, "%{public}s end failed.", __func__);
    ret = extension->OpenFile(uri, mode);
    return ret;
}

int MediaDataShareStubImpl::OpenRawFile(const Uri &uri, const std::string &mode)
{
    MEDIA_DEBUG_LOG("begin.");
    int ret = -1;
    auto client = sptr<MediaDataShareStubImpl>(this);
    auto extension = client->GetOwner();
    CHECK_AND_RETURN_RET_LOG(extension != nullptr, ret, "%{public}s end failed.", __func__);
    ret = extension->OpenRawFile(uri, mode);
    MEDIA_DEBUG_LOG("end successfully. ret: %{public}d", ret);
    return ret;
}

int MediaDataShareStubImpl::Insert(const Uri &uri, const DataShareValuesBucket &value)
{
    int ret = 0;
    auto client = sptr<MediaDataShareStubImpl>(this);
    auto extension = client->GetOwner();
    CHECK_AND_RETURN_RET_LOG(extension != nullptr, ret, "%{public}s end failed.", __func__);
    ret = extension->Insert(uri, value);
    return ret;
}

int MediaDataShareStubImpl::InsertExt(const Uri &uri, const DataShareValuesBucket &value, std::string &result)
{
    int ret = 0;
    auto client = sptr<MediaDataShareStubImpl>(this);
    auto extension = client->GetOwner();
    CHECK_AND_RETURN_RET_LOG(extension != nullptr, ret, "%{public}s end failed.", __func__);
    ret = extension->InsertExt(uri, value, result);
    return ret;
}

int MediaDataShareStubImpl::Update(const Uri &uri, const DataSharePredicates &predicates,
    const DataShareValuesBucket &value)
{
    int ret = 0;
    auto client = sptr<MediaDataShareStubImpl>(this);
    auto extension = client->GetOwner();
    CHECK_AND_RETURN_RET_LOG(extension != nullptr, ret, "%{public}s end failed.", __func__);
    ret = extension->Update(uri, predicates, value);
    return ret;
}

int MediaDataShareStubImpl::Delete(const Uri &uri, const DataSharePredicates &predicates)
{
    int ret = 0;
    auto client = sptr<MediaDataShareStubImpl>(this);
    auto extension = client->GetOwner();
    CHECK_AND_RETURN_RET_LOG(extension != nullptr, ret, "%{public}s end failed.", __func__);
    ret = extension->Delete(uri, predicates);
    return ret;
}

std::shared_ptr<DataShareResultSet> MediaDataShareStubImpl::Query(const Uri &uri,
    const DataSharePredicates &predicates, std::vector<std::string> &columns, DatashareBusinessError &businessError)
{
    auto client = sptr<MediaDataShareStubImpl>(this);
    auto extension = client->GetOwner();
    CHECK_AND_RETURN_RET_LOG(extension != nullptr, nullptr, "%{public}s end failed.", __func__);
    return extension->Query(uri, predicates, columns, businessError);
}

std::string MediaDataShareStubImpl::GetType(const Uri &uri)
{
    MEDIA_DEBUG_LOG("begin.");
    std::string ret = "";
    auto client = sptr<MediaDataShareStubImpl>(this);
    auto extension = client->GetOwner();
    CHECK_AND_RETURN_RET_LOG(extension != nullptr, ret, "%{public}s end failed.", __func__);
    ret = extension->GetType(uri);
    MEDIA_DEBUG_LOG("end successfully.");
    return ret;
}

int MediaDataShareStubImpl::BatchInsert(const Uri &uri, const std::vector<DataShareValuesBucket> &values)
{
    MEDIA_DEBUG_LOG("begin.");
    int ret = 0;
    auto client = sptr<MediaDataShareStubImpl>(this);
    auto extension = client->GetOwner();
    CHECK_AND_RETURN_RET_LOG(extension != nullptr, ret, "%{public}s end failed.", __func__);
    ret = extension->BatchInsert(uri, values);
    MEDIA_DEBUG_LOG("end successfully.");
    return ret;
}

bool MediaDataShareStubImpl::RegisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver)
{
    MEDIA_DEBUG_LOG("begin.");
    bool ret = false;
    auto client = sptr<MediaDataShareStubImpl>(this);
    auto extension = client->GetOwner();
    CHECK_AND_RETURN_RET_LOG(extension != nullptr, ret, "%{public}s end failed.", __func__);
    ret = extension->RegisterObserver(uri, dataObserver);
    MEDIA_DEBUG_LOG("end successfully. ret: %{public}d", ret);
    return ret;
}

bool MediaDataShareStubImpl::UnregisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver)
{
    MEDIA_DEBUG_LOG("begin.");
    bool ret = false;
    auto client = sptr<MediaDataShareStubImpl>(this);
    auto extension = client->GetOwner();
    CHECK_AND_RETURN_RET_LOG(extension != nullptr, ret, "%{public}s end failed.", __func__);
    ret = extension->UnregisterObserver(uri, dataObserver);
    MEDIA_DEBUG_LOG("end successfully. ret: %{public}d", ret);
    return ret;
}

bool MediaDataShareStubImpl::NotifyChange(const Uri &uri)
{
    MEDIA_DEBUG_LOG("begin.");
    bool ret = false;
    auto client = sptr<MediaDataShareStubImpl>(this);
    auto extension = client->GetOwner();
    CHECK_AND_RETURN_RET_LOG(extension != nullptr, ret, "%{public}s end failed.", __func__);
    ret = extension->NotifyChange(uri);
    MEDIA_DEBUG_LOG("end successfully. ret: %{public}d", ret);
    return ret;
}

Uri MediaDataShareStubImpl::NormalizeUri(const Uri &uri)
{
    MEDIA_DEBUG_LOG("begin.");
    Uri urivalue("");
    auto client = sptr<MediaDataShareStubImpl>(this);
    auto extension = client->GetOwner();
    CHECK_AND_RETURN_RET_LOG(extension != nullptr, urivalue, "%{public}s end failed.", __func__);
    urivalue = extension->NormalizeUri(uri);
    MEDIA_DEBUG_LOG("end successfully.");
    return urivalue;
}

Uri MediaDataShareStubImpl::DenormalizeUri(const Uri &uri)
{
    MEDIA_DEBUG_LOG("begin.");
    Uri urivalue("");
    auto client = sptr<MediaDataShareStubImpl>(this);
    auto extension = client->GetOwner();
    CHECK_AND_RETURN_RET_LOG(extension != nullptr, urivalue, "%{public}s end failed.", __func__);
    urivalue = extension->DenormalizeUri(uri);
    MEDIA_DEBUG_LOG("end successfully.");
    return urivalue;
}
} // namespace DataShare
} // namespace OHOS
