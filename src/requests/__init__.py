#   __
#  /__)  _  _     _   _ _/   _
# / (   (- (/ (/ (- _)  /  _)
#          /

"""
Requests HTTP Library
~~~~~~~~~~~~~~~~~~~~~

Requests is an HTTP library, written in Python, for human beings.
Basic GET usage:

   >>> import requests
   >>> r = requests.get('https://www.python.org')
   >>> r.status_code
   200
   >>> b'Python is a programming language' in r.content
   True

... or POST:

   >>> payload = dict(key1='value1', key2='value2')
   >>> r = requests.post('https://httpbin.org/post', data=payload)
   >>> print(r.text)
   {
     ...
     "form": {
       "key1": "value1",
       "key2": "value2"
     },
     ...
   }

The other HTTP methods are supported - see `requests.api`. Full documentation
is at <https://requests.readthedocs.io>.

:copyright: (c) 2017 by Kenneth Reitz.
:license: Apache 2.0, see LICENSE for more details.
"""

# 导入警告处理模块
import warnings

# 导入urllib3（HTTP客户端核心依赖）
import urllib3

# 导入requests自定义的依赖警告异常
from .exceptions import RequestsDependencyWarning

# 尝试导入字符编码检测库charset_normalizer及其版本
try:
    from charset_normalizer import __version__ as charset_normalizer_version
except ImportError:
    # 导入失败时版本置为None
    charset_normalizer_version = None

# 尝试导入传统字符编码检测库chardet及其版本
try:
    from chardet import __version__ as chardet_version
except ImportError:
    # 导入失败时版本置为None
    chardet_version = None


def check_compatibility(urllib3_version, chardet_version, charset_normalizer_version):
    """
    检查核心依赖库的版本兼容性，确保满足requests的最低版本要求
    
    Args:
        urllib3_version (str): urllib3库的版本字符串
        chardet_version (str|None): chardet库的版本字符串（未安装则为None）
        charset_normalizer_version (str|None): charset_normalizer库的版本字符串（未安装则为None）
    
    Raises:
        AssertionError: 当依赖版本不满足要求时触发
    """
    # 将urllib3版本字符串拆分为版本号列表（如"1.26.12" -> ["1","26","12"]）
    urllib3_version = urllib3_version.split(".")
    # 验证urllib3不是从git开发版安装（开发版版本为["dev"]）
    assert urllib3_version != ["dev"]

    # 兼容urllib3仅返回两位版本号的情况（如"16.1" -> ["16","1","0"]）
    if len(urllib3_version) == 2:
        urllib3_version.append("0")

    # 检查urllib3版本兼容性（要求>=1.21.1）
    major, minor, patch = urllib3_version  # 解包主、次、修订版本号
    major, minor, patch = int(major), int(minor), int(patch)  # 转换为整数
    assert major >= 1  # 主版本号至少为1
    if major == 1:
        assert minor >= 21  # 主版本为1时，次版本号至少为21

    # 检查字符编码检测库版本兼容性
    if chardet_version:
        # 若安装了chardet，要求版本>=3.0.2且<6.0.0
        major, minor, patch = chardet_version.split(".")[:3]
        major, minor, patch = int(major), int(minor), int(patch)
        assert (3, 0, 2) <= (major, minor, patch) < (6, 0, 0)
    elif charset_normalizer_version:
        # 若安装了charset_normalizer，要求版本>=2.0.0且<4.0.0
        major, minor, patch = charset_normalizer_version.split(".")[:3]
        major, minor, patch = int(major), int(minor), int(patch)
        assert (2, 0, 0) <= (major, minor, patch) < (4, 0, 0)
    else:
        # 若两个字符编码检测库都未安装，发出警告
        warnings.warn(
            "Unable to find acceptable character detection dependency "
            "(chardet or charset_normalizer).",
            RequestsDependencyWarning,
        )


def _check_cryptography(cryptography_version):
    """
    检查cryptography库版本，低版本（<1.3.4）会导致性能问题，需发出警告
    
    Args:
        cryptography_version (str): cryptography库的版本字符串
    """
    # 目标：检测cryptography < 1.3.4的情况
    try:
        # 将版本字符串转换为整数列表（如"1.3.3" -> [1,3,3]）
        cryptography_version = list(map(int, cryptography_version.split(".")))
    except ValueError:
        # 版本格式异常时直接返回，不处理
        return

    # 若版本低于1.3.4，发出性能警告
    if cryptography_version < [1, 3, 4]:
        warning = "Old version of cryptography ({}) may cause slowdown.".format(
            cryptography_version
        )
        warnings.warn(warning, RequestsDependencyWarning)


# ========== 核心依赖兼容性检查 ==========
try:
    # 执行依赖版本兼容性检查
    check_compatibility(
        urllib3.__version__, chardet_version, charset_normalizer_version
    )
except (AssertionError, ValueError):
    # 版本不兼容时发出警告，提示用户升级依赖
    warnings.warn(
        "urllib3 ({}) or chardet ({})/charset_normalizer ({}) doesn't match a supported "
        "version!".format(
            urllib3.__version__, chardet_version, charset_normalizer_version
        ),
        RequestsDependencyWarning,
    )

# ========== SNI（Server Name Indication）支持兼容处理 ==========
# 背景：SNI是TLS扩展，用于单IP多域名的HTTPS服务，需确保urllib3支持
try:
    try:
        # 尝试导入标准库ssl模块
        import ssl
    except ImportError:
        # 无ssl模块时置为None
        ssl = None

    # 若标准库ssl不支持SNI（HAS_SNI为False）
    if not getattr(ssl, "HAS_SNI", False):
        # 从urllib3导入pyopenssl扩展，注入到urllib3以提供SNI支持
        from urllib3.contrib import pyopenssl
        pyopenssl.inject_into_urllib3()

        # 检查cryptography版本（pyopenssl依赖cryptography）
        from cryptography import __version__ as cryptography_version
        _check_cryptography(cryptography_version)
except ImportError:
    # 缺少pyopenssl/cryptography时跳过SNI兼容处理
    pass

# ========== 警告过滤配置 ==========
# 忽略urllib3自身的DependencyWarning（避免冗余警告）
from urllib3.exceptions import DependencyWarning
warnings.simplefilter("ignore", DependencyWarning)

# ========== 日志初始化 ==========
# 设置默认日志处理器，避免运行时出现"No handler found"警告
import logging
from logging import NullHandler

# ========== 导出核心模块/属性 ==========
# 导入内部工具包和模块
from . import packages, utils
# 导入版本、作者等元信息
from .__version__ import (
    __author__,
    __author_email__,
    __build__,
    __cake__,
    __copyright__,
    __description__,
    __license__,
    __title__,
    __url__,
    __version__,
)
# 导入HTTP方法快捷函数（对外暴露的核心API）
from .api import delete, get, head, options, patch, post, put, request
# 导入异常类（对外暴露的异常类型）
from .exceptions import (
    ConnectionError,
    ConnectTimeout,
    FileModeWarning,
    HTTPError,
    JSONDecodeError,
    ReadTimeout,
    RequestException,
    Timeout,
    TooManyRedirects,
    URLRequired,
)
# 导入请求/响应模型类
from .models import PreparedRequest, Request, Response
# 导入会话类（核心功能载体）
from .sessions import Session, session
# 导入HTTP状态码常量
from .status_codes import codes

# 为requests根日志器添加空处理器，避免无日志配置时的警告
logging.getLogger(__name__).addHandler(NullHandler())

# 配置FileModeWarning的警告级别为默认，确保该警告能正常触发
warnings.simplefilter("default", FileModeWarning, append=True)
