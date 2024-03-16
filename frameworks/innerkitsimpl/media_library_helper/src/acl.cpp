/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#include "acl.h"

#include <cerrno>
#include <new>
#include <type_traits>
#include <sys/stat.h>
#include <sys/xattr.h>

#include "medialibrary_errno.h"
#include "media_log.h"
#include "securec.h"

namespace OHOS {
namespace Media {
ACL_PERM Acl::ReCalcMaskPerm()
{
    ACL_PERM perm;
    for (const auto &e : entries) {
        if (e.tag == ACL_TAG::USER || e.tag == ACL_TAG::GROUP_OBJ || e.tag == ACL_TAG::GROUP) {
            perm.Merge(e.perm);
        }
    }
    return perm;
}

bool Acl::IsEmpty()
{
    return entries.empty();
}

bool Acl::IsValid()
{
    if (!entries.count(ACL_TAG::USER_OBJ) || !entries.count(ACL_TAG::GROUP_OBJ) ||
            !entries.count(ACL_TAG::OTHER)) {
        return false;
    }
    if (maskDemand && !entries.count(ACL_TAG::MASK)) {
        return false;
    }
    return true;
}

void Acl::CompareInsertEntry(const AclXattrEntry &entry)
{
    if (entries.count(entry)) {
        auto it = entries.find(entry);
        entries.erase(it);
    }
    if (entry.perm.IsReadable() || entry.perm.IsWritable() || entry.perm.IsExecutable()) {
        entries.insert(entry);
    }
}

int Acl::InsertEntry(const AclXattrEntry &entry)
{
    if (entries.size() >= ENTRIES_MAX_NUM) {
        errno = EAGAIN;
        return E_ERR;
    }
    CompareInsertEntry(entry); // must before ReCalcMaskPerm()
    
    maskDemand++;
    /*
        * In either case there's no or already one ACL_MASK entry in the set,
        * we need to re-calculate MASK's permission and *insert* it (to replace
        * the old one in latter case since we can't change std::set's element
        * in-place). So do the following unconditionally.
        *
        * Be warned: do _NOT_ combine the following into one line, otherwise
        * you can't pass the !!genius!! CI coding style check.
        */
    CompareInsertEntry(
        { ACL_TAG::MASK, ReCalcMaskPerm(), ACL_UNDEFINED_ID }
    );
    return E_OK;
}

char *Acl::Serialize(size_t &bufSize)
{
    if (!IsValid()) {
        errno = EINVAL;
        return nullptr;
    }

    /* clear possible previous allocation */
    if (buf != nullptr) {
        delete[] buf;
        buf = nullptr;
    }

    bufSize = sizeof(AclXattrHeader) + sizeof(AclXattrEntry) * entries.size();
    if (bufSize > BUF_MAX_SIZE) {
        bufSize = 0;
        errno = EINVAL;
        return nullptr;
    }
    buf = new (std::nothrow) char[bufSize];
    if (buf == nullptr) {
        errno = ENOMEM;
        return nullptr;
    }
    auto err = memcpy_s(buf, bufSize, &header, sizeof(AclXattrHeader));
    if (err != EOK) {
        errno = err;
        delete[] buf;
        buf = nullptr;
        return nullptr;
    }

    size_t restSize = bufSize - sizeof(AclXattrHeader);
    AclXattrEntry *ptr = reinterpret_cast<AclXattrEntry *>(buf + sizeof(AclXattrHeader));
    for (const auto &e : entries) {
        auto err = memcpy_s(ptr++, restSize, &e, sizeof(AclXattrEntry));
        if (err != EOK) {
            errno = err;
            delete[] buf;
            buf = nullptr;
            return nullptr;
        }
        restSize -= sizeof(AclXattrEntry);
    }
    return buf;
}

Acl AclFromMode(const std::string &file)
{
    Acl acl;
    struct stat st;

    if (stat(file.c_str(), &st) == -1) {
        return acl;
    }

    acl.InsertEntry(
        {
        .tag = ACL_TAG::USER_OBJ,
        .perm = (st.st_mode & S_IRWXU) >> 6,
        .id = ACL_UNDEFINED_ID,
        }
    );
    acl.InsertEntry(
        {
        .tag = ACL_TAG::GROUP_OBJ,
        .perm = (st.st_mode & S_IRWXG) >> 3,
        .id = ACL_UNDEFINED_ID,
        }
    );
    acl.InsertEntry(
        {
        .tag = ACL_TAG::OTHER,
        .perm = (st.st_mode & S_IRWXO),
        .id = ACL_UNDEFINED_ID,
        }
    );

    return acl;
}

void InitSandboxEntry(AclXattrEntry &entry)
{
    entry.tag = ACL_TAG::GROUP;
    entry.id = THUMB_ACL_GROUP;
    entry.perm.SetR();
    entry.perm.SetE();
}

void InitSandboxGroupEntry(AclXattrEntry& entry, uint32_t id, uint16_t access)
{
    entry.tag = ACL_TAG::GROUP;
    entry.id = id;
    if (access & ACL_PERM::Value::READ) {
       entry.perm.SetR();
    }
    if (access & ACL_PERM::Value::WRITE) {
       entry.perm.SetW();
    }
    if (access & ACL_PERM::Value::EXECUTE) {
       entry.perm.SetE();
    }
}

int32_t Acl::AclSetDefault()
{
    AclXattrEntry entry = {};
    InitSandboxGroupEntry(entry, THUMB_ACL_GROUP, ACL_PERM::READ | ACL_PERM::Value::EXECUTE);
    int32_t err = EntryInsertHelper(entry, THUMB_DIR);
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to set the acl permission for the Photo dir");
    }
    return err;
}

int32_t Acl::AclSetDB()
{
    AclXattrEntry dbEntry = {};
    InitSandboxGroupEntry(dbEntry, MEDIA_DB_ACL_GROUP, ACL_PERM::READ | ACL_PERM::Value::WRITE |
        ACL_PERM::Value::EXECUTE);
    int32_t err = EntryInsertHelper(dbEntry, DB_DIR);
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to set the acl permission for the database");
    }
    return err;
}

int32_t Acl::EntryInsertHelper(AclXattrEntry& entry, con`st std::string& path)
{
    /* init acl from file's mode */
    Acl acl = AclFromMode(path);
    if (acl.IsEmpty()) {
        MEDIA_ERR_LOG("Failed to generate ACL from file's mode: %{public}s", std::strerror(errno));
        return E_ERR;
    }

    /* add new entry into set */
    if (acl.InsertEntry(entry) == E_ERR) {
        MEDIA_ERR_LOG("Failed to insert new entry into ACL: %{public}s", std::strerror(errno));
        return E_ERR;
    }

    /* transform to binary and write to file */
    size_t bufSize;
    char *buf = acl.Serialize(bufSize);
    if (buf == nullptr) {
        MEDIA_ERR_LOG("Failed to serialize ACL into binary: %{public}s", std::strerror(errno));
        return E_ERR;
    }
    if (setxattr(path.c_str(), ACL_XATTR_DEFAULT, buf, bufSize, 0) == -1) {
        MEDIA_ERR_LOG("Failed to write into file's xattr: %{public}s", std::strerror(errno));
        return E_ERR;
    }
    return E_OK;
}

void Acl::listAttr(const std::string& path)
{
    char* buf;
    char* key;
    char* val;
    size_t bufLen;
    size_t keyLen;
    size_t valLen;

    bufLen = listxattr(path.c_str(), NULL, 0);
    if (bufLen < 0) {
        MEDIA_ERR_LOG("path:%{private}s listAttr fail", path.c_str());
        return;
    }

    if (bufLen == 0) {
        MEDIA_ERR_LOG("path:%{private}s listAttr fail", path.c_str());
        return;
    }

    buf = static_cast<char*>(malloc(bufLen));
    if (buf == NULL) {
        MEDIA_ERR_LOG("path:%{private}s, malloc error", path.c_str());
        return;
    }

    bufLen = listxattr(path.c_str(), buf, bufLen);
    if (bufLen < 0) {
        MEDIA_ERR_LOG("path:%{private}s, listAttr fail", path.c_str());
    }

    key = buf;
    while (bufLen > 0) {
        valLen = getxattr(path.c_str(), key, NULL, 0);
        if (valLen == -1) {
            MEDIA_ERR_LOG("path:%{private}s, get attr error", path.c_str());
            return;
        }
        if (valLen > 0) {
            
            // one extra byte to append 0x00
            val = static_cast<char*>(malloc(valLen + 1));
            if (val == nullptr) {
                MEDIA_ERR_LOG("path:%{private}s, malloc error", path.c_str());
                return;
            }
            valLen = getxattr(path.c_str(), key, val, valLen);
            if (valLen == -1) {
                MEDIA_ERR_LOG("path:%{private}s, get attr error", path.c_str());
                return;
            } else {
                val[valLen] = 0;
                MEDIA_DEBUG_LOG("path:%{private}s, value:%{public}s", path.c_str(), val);
            }
            free(val);
        } else if (valLen == 0) {
            MEDIA_DEBUG_LOG("path:%{private}s, no value", path.c_str(), val);
        }
        keyLen = strlen(key) + 1;
        bufLen -= keyLen;
        key += keyLen;
    }
    free(buf);
}

Acl::~Acl()
{
    if (buf != nullptr) {
        delete[] buf;
        buf = nullptr;
    }
}
} // MEDIA
} // OHOS
