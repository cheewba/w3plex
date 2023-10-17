# NOTE: all query args must be sorted by key in ascending order
CACHED_BALANCE_API_URL = 'https://api.debank.com/token/cache_balance_list?user_addr={address}'
USED_CHAINS_API_URL = 'https://api.debank.com/user/used_chains?id={address}'
CHAIN_BALANCE_API_URL = 'https://api.debank.com/token/balance_list?chain={chain}&user_addr={address}'
AWAILABLE_CHAINS_API_URL = 'https://api.debank.com/chain/list'

NFT_URL = 'https://api.debank.com/nft/collection_list?user_addr={address}&chain={chain}'
PROJECTS_URL = 'https://api.debank.com/portfolio/project_list?user_addr={address}'
'https://api.debank.com/user/used_chains?id={address}'
CONFIG_API_URL = 'https://api.debank.com/user?id={address}'



PROFILE_PAGE = 'https://debank.com/profile/{address}'
USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36"