/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License"){return 0;}
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

#ifndef OHOS_MEDIALIBRARY_TRIGGER_H
#define OHOS_MEDIALIBRARY_TRIGGER_H

#include "medialibrary_rdb_transaction.h"
#include "medialibrary_trigger_utils.h"
#include "photo_asset_change_info.h"
#include "album_change_info.h"

namespace OHOS {
namespace Media {

class TriggerHelper {
public:
    void AddFocusedColumnName(const std::unordered_set<std::string>& focusedColumnNames);
    std::vector<std::string> GetFocusedColumnNamesVec() const;
    std::unordered_set<std::string> GetFocusedColumnNames() const;
    void SetName(const std::string& name) {name_ = name;}
    std::string GetName() {return name_;}
private:
    std::unordered_set<std::string> focusedColumnNames_;
    std::string name_;
};

class MediaLibraryTriggerBase : public TriggerHelper {
public:
    virtual ~MediaLibraryTriggerBase() {}
    virtual int32_t Process(std::shared_ptr<TransactionOperations> trans,
        const std::vector<AccurateRefresh::PhotoAssetChangeData>& changeDataVec) {return NativeRdb::E_ERROR;}
    virtual int32_t Process(std::shared_ptr<TransactionOperations> trans,
        const std::vector<AccurateRefresh::AlbumChangeData>& changeDataVec) {return NativeRdb::E_ERROR;}
    virtual bool isTriggerFireForRow(std::shared_ptr<TransactionOperations> trans,
        const AccurateRefresh::PhotoAssetChangeData& changeData) {return false;}
    virtual bool isTriggerFireForRow(std::shared_ptr<TransactionOperations> trans,
        const AccurateRefresh::AlbumChangeData& changeData) {return false;}
};

class MediaLibraryTrigger : public MediaLibraryTriggerBase {
friend class MediaLibraryTriggerManager;
public:
    MediaLibraryTrigger();
    int32_t Process(std::shared_ptr<TransactionOperations> trans,
        const std::vector<AccurateRefresh::PhotoAssetChangeData>& changeDataVec) override;
    bool isTriggerFireForRow(std::shared_ptr<TransactionOperations> trans,
        const AccurateRefresh::PhotoAssetChangeData& changeData) override;

private:
    bool Init(const std::vector<std::shared_ptr<MediaLibraryTriggerBase> >& triggers, const std::string& table);
    std::vector<std::shared_ptr<MediaLibraryTriggerBase> > triggers_;
    std::string table_;
};

class InsertSourcePhotoCreateSourceAlbumTrigger : public MediaLibraryTriggerBase {
public:
    InsertSourcePhotoCreateSourceAlbumTrigger();
    int32_t Process(std::shared_ptr<TransactionOperations> trans,
        const std::vector<AccurateRefresh::PhotoAssetChangeData>& changeDataVec) override;
    bool isTriggerFireForRow(std::shared_ptr<TransactionOperations> trans,
        const AccurateRefresh::PhotoAssetChangeData& changeData) override;

private:
    bool CollectPackageInfo(std::shared_ptr<TransactionOperations> trans,
        const std::string& packageName, const std::string& ownerPackage);
    bool GetLPathFromAlbumPlugin(std::shared_ptr<TransactionOperations> trans,
        const std::string& packageName, const std::string& ownerPackage);
    bool GetSourceAlbumCntByLPath(std::shared_ptr<TransactionOperations> trans,
        const std::string& packageName, const std::string& ownerPackage);
    bool DeleteFromPhotoAlbum(std::shared_ptr<TransactionOperations> trans);
    bool InsertIntoPhotoAlbum(std::shared_ptr<TransactionOperations> trans);
    bool UpdatePhotoOwnerAlbumId(std::shared_ptr<TransactionOperations> trans);
    bool QueryAlbumIdByLPath(std::shared_ptr<TransactionOperations> trans);
    bool Notify();
    bool CheckValid() const;
private:
    struct PackageInfo {
        std::string lPath;
        std::string packageName;
        std::string ownerPackage;
        int albumCnt  = -1;
        bool IsValid() const;
        std::string ToString() const;
        bool IsPackageNameValid() const {return packageName != "";}
        bool IsLPathValid() const {return lPath != "";}
        bool IsAlbumCntValid() const {return albumCnt != -1;}
    };
    std::unordered_map<std::string, PackageInfo> packageInfoMap_;
    std::unordered_map<std::string, int32_t> lPathAlbumIdMap_;
    std::vector<std::string> triggeredFileIds_;
};

class InsertPhotoUpdateAlbumBundleNameTrigger : public MediaLibraryTriggerBase {
public:
    InsertPhotoUpdateAlbumBundleNameTrigger();
    int32_t Process(std::shared_ptr<TransactionOperations> trans,
        const std::vector<AccurateRefresh::PhotoAssetChangeData>& changeDataVec) override;
    bool isTriggerFireForRow(std::shared_ptr<TransactionOperations> trans,
        const AccurateRefresh::PhotoAssetChangeData& changeData) override;
private:
    struct PackageInfo {
        std::string packageName;
        std::string ownerPackage;
        int albumWoBundleNameCnt = -1;
        bool IsValid() const;
    };
    bool isAlbumWoBundleName(std::shared_ptr<TransactionOperations> trans, const std::string& packageName);
    std::unordered_map<std::string, PackageInfo> packageInfoMap_;
};
} // namespace Media
} // namespace OHOS
#endif //OHOS_MEDIALIBRARY_TRIGGER_H