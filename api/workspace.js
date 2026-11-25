// © Nasser Aldin Farag (0xFarag). All rights reserved.
'use strict';
// The operator provisions and controls the durable Team origin. No request input becomes a destination.
module.exports = function(req,res) {
  res.setHeader('Cache-Control','no-store');
  if(req.method !== 'GET') return res.status(405).json({available:false});
  try {
    const url=new URL(process.env.AUTHZLEDGER_TEAM_ORIGIN);
    if(url.protocol!=='https:'||url.username||url.password||url.pathname!=='/'||url.search||url.hash)
      throw new Error('invalid origin');
    return res.status(200).json({available:true,origin:url.origin});
  } catch { return res.status(200).json({available:false}); }
};
