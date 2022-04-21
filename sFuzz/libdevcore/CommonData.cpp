/*
    This file is part of cpp-ethereum.

    cpp-ethereum is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    cpp-ethereum is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with cpp-ethereum.  If not, see <http://www.gnu.org/licenses/>.
*/
/** @file CommonData.cpp
 * @author Gav Wood <i@gavwood.com>
 * @date 2014
 */

#include "CommonData.h"
#include <random>

#include "Exceptions.h"

using namespace std;
using namespace dev;

namespace
{
int fromHexChar(char _i) noexcept
{
    if (_i >= '0' && _i <= '9')
        return _i - '0';
    if (_i >= 'a' && _i <= 'f')
        return _i - 'a' + 10;
    if (_i >= 'A' && _i <= 'F')
        return _i - 'A' + 10;
    return -1;
}
}  // namespace

bool dev::isHex(string const& _s) noexcept
{
    auto it = _s.begin();
    if (_s.compare(0, 2, "0x") == 0)
        it += 2;
    return std::all_of(it, _s.end(), [](char c) { return fromHexChar(c) != -1; });
}

std::string dev::escaped(std::string const& _s, bool _all)
{
    static const map<char, char> prettyEscapes{{'\r', 'r'}, {'\n', 'n'}, {'\t', 't'}, {'\v', 'v'}};
    std::string ret;
    ret.reserve(_s.size() + 2);
    ret.push_back('"');
    for (auto i : _s)
        if (i == '"' && !_all)
            ret += "\\\"";
        else if (i == '\\' && !_all)
            ret += "\\\\";
        else if (prettyEscapes.count(i) && !_all)
        {
            ret += '\\';
            ret += prettyEscapes.find(i)->second;
        }
        else if (i < ' ' || _all)
        {
            ret += "\\x";
            ret.push_back("0123456789abcdef"[(uint8_t)i / 16]);
            ret.push_back("0123456789abcdef"[(uint8_t)i % 16]);
        }
        else
            ret.push_back(i);
    ret.push_back('"');
    return ret;
}


bytes dev::fromHex(std::string const& _s, WhenError _throw)
{
    unsigned s = (_s.size() >= 2 && _s[0] == '0' && _s[1] == 'x') ? 2 : 0;
    std::vector<uint8_t> ret;
    ret.reserve((_s.size() - s + 1) / 2);

    if (_s.size() % 2)
    {
        int h = fromHexChar(_s[s++]);
        if (h != -1)
            ret.push_back(h);
        else if (_throw == WhenError::Throw)
            BOOST_THROW_EXCEPTION(BadHexCharacter());
        else
            return bytes();
    }
    for (unsigned i = s; i < _s.size(); i += 2)
    {
        int h = fromHexChar(_s[i]);
        int l = fromHexChar(_s[i + 1]);
        if (h != -1 && l != -1)
            ret.push_back((byte)(h * 16 + l));
        else if (_throw == WhenError::Throw)
            BOOST_THROW_EXCEPTION(BadHexCharacter());
        else
            return bytes();
    }
    return ret;
}

std::pair<bytes, std::string> dev::fromHex(
    std::string const& _s, std::string const& _l, u160 libAddr, WhenError _throw)
{
    unsigned s = (_s.size() >= 2 && _s[0] == '0' && _s[1] == 'x') ? 2 : 0;
    std::vector<uint8_t> ret;
    unsigned hexSize = (_s.size() - s + 1) / 2;
    ret.reserve(hexSize);

    // printf("size: %d\n", _s.size());
    if (_s.size() % 2)
    {
        int h = fromHexChar(_s[s++]);  // first char
        // printf("%d ,", h);
        if (h != -1)
            ret.push_back(h);
        else if (_throw == WhenError::Throw)
            BOOST_THROW_EXCEPTION(BadHexCharacter());
        else
        {
            // printf("\nfailed in first char!");
            return make_pair(bytes(), "");
        }
    }
    int r = 0;
    // bool record = false;
    // for (unsigned i = s; i < _s.size() && ret.size() + 2 < hexSize; i += 2)
    for (unsigned i = s; ret.size() < hexSize; i += 2)
    {
        int h, l;
        if (i < _s.size())
        {
            h = fromHexChar(_s[i]);
            l = fromHexChar(_s[i + 1]);
        }
        else
        {
            h = 0;
            l = 0;
        }

        /* debug */
        // int lr = r;
        r = h * 16 + l;
        // if (lr == 88 && r == 32)
        //     record = true;
        // if (record)
        //     printf("%c%c,", _s[i], _s[i + 1]);
        // printf("%d,", r);

        if (h != -1 && l != -1)
            ret.push_back((byte)r);
        else if (_throw == WhenError::Throw)
            BOOST_THROW_EXCEPTION(BadHexCharacter());
        else if (_s[i] == '_' && _s[i + 1] == '_')
        {
            std::string libPath = _s.substr(i + 2, 38);
            std::string libName = libPath.substr(0, libPath.find("__"));
            /* debug */
            // printf("Path : %s\n", libPath.c_str());
            // printf("libName :%s\n", libName.c_str());
            // printf("_l first:%s\n", _l.substr(0, _l.find("_")).c_str());
            // printf("Bin:%s\n", _l.substr(_l.find("_") + 1, _l.size()).c_str());
            if (_l != libName)
                return make_pair(bytes(), libName);
            // printf("start decode libbin\n");
            // auto libBin = fromHex2(_l.substr(_l.find("_") + 1, _l.size()), "").first;
            // printf("decode libbin success: %d\n", libBin.size());
            // hexSize += libBin.size();
            // hexSize -= 6;
            hexSize += 2;
            for (unsigned j = 0; j < 19; j++)
                ret.push_back((byte)0);
            ret.push_back((byte)libAddr);
            // for (auto k : libBin)
            // {
            //     ret.push_back((byte)k);
            //     // printf("%d ,", k);
            // }
            // printf("\n");
            i += 40;
        }
        else
        {
            // printf("\nfailed!");
            return make_pair(bytes(), "");
        }
    }
    // printf("\nConvert success!\n");
    return make_pair(ret, "");
}

bytes dev::asNibbles(bytesConstRef const& _s)
{
    std::vector<uint8_t> ret;
    ret.reserve(_s.size() * 2);
    for (auto i : _s)
    {
        ret.push_back(i / 16);
        ret.push_back(i % 16);
    }
    return ret;
}

std::string dev::toString(string32 const& _s)
{
    std::string ret;
    for (unsigned i = 0; i < 32 && _s[i]; ++i)
        ret.push_back(_s[i]);
    return ret;
}
